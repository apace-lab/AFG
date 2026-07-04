//! Companion to `llm_api_finder`: scans JavaScript/TypeScript *source text*
//! (not MIR — RUPTA and rustc's MIR have no concept of JS) for LLM API call
//! sites. This exists because a large share of Tauri/Electron-style desktop
//! LLM apps put all chat logic in the JS/TS frontend and use the Rust side
//! only for windowing — those calls are invisible to `find_llm_calls` no
//! matter how good RUPTA's analysis is, since they never appear in a Rust
//! binary at all.
//!
//! Same text-scanning philosophy as the MIR scanner (regex against a curated
//! signature catalogue, not a full parse/typecheck), extended with an
//! import-statement check used to grade confidence: a call to a generic
//! method name (`chat`, `invoke`, `call`) is only reported when the file
//! also imports the SDK package that name belongs to; a distinctive
//! multi-segment call (`chat.completions.create`) is reported either way.

use crate::provider_hints::find_provider_hint;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCallSig {
    pub library: String,
    pub pattern: String,
    pub kind: String,
    pub packages: Vec<String>,
    pub require_import: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCallSite {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsApiMatch {
    pub library: String,
    pub pattern: String,
    pub kind: String,
    /// "call+import" | "call-only" | "http+path-hint" | "http-call-only"
    pub match_strategy: String,
    pub callsite: JsCallSite,
    pub raw_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Report every fetch()/axios()/http(s).request() call site, even when no
    /// known LLM REST path suffix is found nearby. Off by default: unlike
    /// Rust programs (where a raw reqwest call is already a fairly deliberate
    /// signal), ordinary frontend code calls fetch() constantly for reasons
    /// that have nothing to do with LLMs, so unconditional reporting is noise
    /// rather than signal.
    pub all_http_calls: bool,
    /// Descend into node_modules. Off by default (vendored dependency source
    /// isn't the target's own code and is usually enormous).
    pub include_node_modules: bool,
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load all JS/TS LLM call signatures from
/// `datasets_path/llm_api_functions_js.json`.
pub fn load_js_signatures(datasets_path: &Path) -> Result<Vec<JsCallSig>, Box<dyn Error>> {
    let json_path = datasets_path.join("llm_api_functions_js.json");
    let content = fs::read_to_string(&json_path)
        .map_err(|e| format!("cannot read {}: {}", json_path.display(), e))?;
    let data: HashMap<String, serde_json::Value> = serde_json::from_str(&content)?;

    let mut sigs = Vec::new();
    for (lib_name, entry) in &data {
        if lib_name.starts_with('_') {
            continue;
        }
        let packages: Vec<String> = entry
            .get("packages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let Some(calls) = entry.get("calls").and_then(|v| v.as_array()) else {
            continue;
        };
        for call in calls {
            let pattern = call
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if pattern.is_empty() {
                continue;
            }
            let kind = call
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let require_import = call
                .get("require_import")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            sigs.push(JsCallSig {
                library: lib_name.clone(),
                pattern,
                kind,
                packages: packages.clone(),
                require_import,
            });
        }
    }
    Ok(sigs)
}

// ── Regexes ───────────────────────────────────────────────────────────────────

// import x from 'pkg' | import {a} from "pkg" | import 'pkg' | require('pkg') | import('pkg')
static RE_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\bfrom\s+|\brequire\(\s*|\bimport\(\s*|\bimport\s+)['"]([^'"]+)['"]"#).unwrap()
});

// "..." | '...' | `...`  (template literals treated as opaque text, which is
// fine here since we only ever substring-search the captured text)
static RE_STRING_LIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`"#).unwrap()
});

static RE_HTTP_TRIGGER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|(?:http|https)\.request)\s*\(",
    )
    .unwrap()
});

/// How many lines before/after an HTTP trigger to search for a path literal.
/// URLs are commonly built a few lines above the call (`const url = ...;`
/// then `fetch(url, ...)` a couple of lines later), so the window is
/// asymmetric — mostly looking backward.
const HINT_WINDOW_BEFORE: usize = 6;
const HINT_WINDOW_AFTER: usize = 2;

// ── Scanner ───────────────────────────────────────────────────────────────────

struct CallMatcher<'a> {
    sig: &'a JsCallSig,
    pattern: Regex,
}

fn make_call_matchers(sigs: &[JsCallSig]) -> Vec<CallMatcher<'_>> {
    sigs.iter()
        .filter_map(|sig| {
            let pat = format!(r"{}\s*\(", regex::escape(&sig.pattern));
            Regex::new(&pat)
                .ok()
                .map(|pattern| CallMatcher { sig, pattern })
        })
        .collect()
}

fn collect_imports(content: &str) -> HashSet<String> {
    RE_IMPORT
        .captures_iter(content)
        .map(|c| c[1].to_string())
        .collect()
}

fn import_satisfies(imports: &HashSet<String>, packages: &[String]) -> bool {
    packages.iter().any(|pkg| {
        imports.contains(pkg)
            || imports
                .iter()
                .any(|imp| imp.starts_with(&format!("{pkg}/")))
    })
}

/// Scan one file's already-read source text. `file` is the path/label used in
/// reported callsites; it need not exist on disk (useful for tests).
pub fn scan_js_source(
    file: &str,
    content: &str,
    sigs: &[JsCallSig],
    opts: &ScanOptions,
) -> Vec<JsApiMatch> {
    let imports = collect_imports(content);
    let matchers = make_call_matchers(sigs);

    let lines: Vec<&str> = content.lines().collect();

    // literals[i] = string/template literals found on lines[i] (0-indexed)
    let literals: Vec<Vec<String>> = lines
        .iter()
        .map(|line| {
            RE_STRING_LIT
                .captures_iter(line)
                .map(|c| {
                    c.get(1)
                        .or_else(|| c.get(2))
                        .or_else(|| c.get(3))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default()
                })
                .collect()
        })
        .collect();

    let mut matches = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let lineno = idx + 1;

        // ── SDK call-shape matches ──
        // Collect spans first: some patterns are textual substrings of a more
        // specific pattern in the same library (e.g. openai's legacy
        // "completions.create" is a suffix of "chat.completions.create"), and
        // reporting both for one call site is a duplicate, not a finding.
        // Cross-library overlaps (two SDKs sharing an OpenAI-compatible
        // shape) are kept — that's genuine ambiguity, not redundancy.
        let candidates: Vec<(&CallMatcher, usize, usize)> = matchers
            .iter()
            .filter_map(|m| m.pattern.find(line).map(|mat| (m, mat.start(), mat.end())))
            .collect();

        for (i, (m, start, end)) in candidates.iter().enumerate() {
            let shadowed = candidates
                .iter()
                .enumerate()
                .any(|(j, (other, ostart, oend))| {
                    i != j
                        && other.sig.library == m.sig.library
                        && *ostart <= *start
                        && *end <= *oend
                        && (*ostart, *oend) != (*start, *end)
                });
            if shadowed {
                continue;
            }
            let confirmed = import_satisfies(&imports, &m.sig.packages);
            if m.sig.require_import && !confirmed {
                continue;
            }
            matches.push(JsApiMatch {
                library: m.sig.library.clone(),
                pattern: m.sig.pattern.clone(),
                kind: m.sig.kind.clone(),
                match_strategy: if confirmed {
                    "call+import"
                } else {
                    "call-only"
                }
                .to_string(),
                callsite: JsCallSite {
                    file: file.to_string(),
                    line: lineno,
                },
                raw_line: line.trim().to_string(),
                provider_hint: None,
            });
        }

        // ── raw HTTP calls ──
        if RE_HTTP_TRIGGER.is_match(line) {
            let start = idx.saturating_sub(HINT_WINDOW_BEFORE);
            let end = (idx + HINT_WINDOW_AFTER + 1).min(literals.len());
            let nearby: Vec<&String> = literals[start..end].iter().flatten().collect();
            let hint = find_provider_hint(&nearby);

            if hint.is_some() || opts.all_http_calls {
                matches.push(JsApiMatch {
                    library: "raw-http-fetch".to_string(),
                    pattern: RE_HTTP_TRIGGER
                        .find(line)
                        .map(|m| m.as_str().trim_end_matches('(').trim().to_string())
                        .unwrap_or_default(),
                    kind: "raw HTTP call".to_string(),
                    match_strategy: if hint.is_some() {
                        "http+path-hint"
                    } else {
                        "http-call-only"
                    }
                    .to_string(),
                    callsite: JsCallSite {
                        file: file.to_string(),
                        line: lineno,
                    },
                    raw_line: line.trim().to_string(),
                    provider_hint: hint,
                });
            }
        }
    }

    matches
}

const SCAN_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];

/// Walk `root` (a file or a directory) and scan every JS/TS source file
/// found under it.
pub fn scan_path(
    root: &Path,
    sigs: &[JsCallSig],
    opts: &ScanOptions,
) -> Result<Vec<JsApiMatch>, Box<dyn Error>> {
    let mut matches = Vec::new();

    if root.is_file() {
        let content = fs::read_to_string(root)?;
        return Ok(scan_js_source(
            &root.display().to_string(),
            &content,
            sigs,
            opts,
        ));
    }

    let walker = walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        if !e.file_type().is_dir() {
            return true;
        }
        let name = e.file_name().to_string_lossy();
        if name == ".git" {
            return false;
        }
        if name == "node_modules" && !opts.include_node_modules {
            return false;
        }
        true
    });

    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !SCAN_EXTENSIONS.contains(&ext) {
            continue;
        }
        let content = match fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue, // skip unreadable/non-UTF8 files rather than aborting the whole scan
        };
        matches.extend(scan_js_source(
            &entry.path().display().to_string(),
            &content,
            sigs,
            opts,
        ));
    }

    Ok(matches)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn datasets_path() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("datasets")
            .leak()
    }

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    #[test]
    fn loads_all_js_libraries() {
        let sigs = load_js_signatures(datasets_path()).expect("load_js_signatures failed");
        assert!(!sigs.is_empty());
        let libs: Vec<_> = sigs.iter().map(|s| s.library.as_str()).collect();
        for expected in &["openai", "anthropic", "google-genai", "vercel-ai-sdk"] {
            assert!(libs.contains(expected), "library '{expected}' missing");
        }
    }

    #[test]
    fn detects_openai_with_import() {
        const SRC: &str = r#"
import OpenAI from "openai";
const client = new OpenAI();
const res = await client.chat.completions.create({ model: "gpt-4o", messages: [] });
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("app.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "openai")
            .expect("no openai match");
        assert_eq!(hit.match_strategy, "call+import");
        assert_eq!(hit.pattern, "chat.completions.create");
    }

    #[test]
    fn detects_anthropic_without_explicit_import_line_still_flags_call_only() {
        // Bundled/minified output often loses the import statement while
        // keeping the property-access chain intact.
        const SRC: &str =
            r#"const r=await anthropic.messages.create({model:"claude-3-opus",messages:m});"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("bundle.min.js", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "anthropic")
            .expect("no anthropic match");
        assert_eq!(hit.match_strategy, "call-only");
    }

    #[test]
    fn generic_pattern_requires_import_to_report() {
        // "chat(" alone (cohere-ai / ollama-js shape) is too generic to trust
        // without a confirming import.
        const SRC: &str = r#"function chat(msg) { return ui.chat(msg); }"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("ui.ts", SRC, &sigs, &opts());
        assert!(
            matches
                .iter()
                .all(|m| m.library != "cohere-ai" && m.library != "ollama-js"),
            "generic pattern should not fire without import: {:#?}",
            matches
        );
    }

    #[test]
    fn generic_pattern_fires_once_import_confirms_it() {
        const SRC: &str = r#"
import Cohere from "cohere-ai";
const co = new Cohere();
const res = await co.chat({ message: "hi" });
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("bot.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "cohere-ai")
            .expect("no cohere match");
        assert_eq!(hit.match_strategy, "call+import");
    }

    #[test]
    fn raw_fetch_with_known_path_gets_hint() {
        const SRC: &str = r#"
const url = `${apiBase}/v1/chat/completions`;
const res = await fetch(url, { method: "POST", body: JSON.stringify(payload) });
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("client.js", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "raw-http-fetch")
            .expect("no raw-http-fetch match");
        assert_eq!(hit.match_strategy, "http+path-hint");
        assert!(hit.provider_hint.as_deref().unwrap().contains("OpenAI"));
    }

    #[test]
    fn raw_fetch_without_known_path_is_suppressed_by_default() {
        const SRC: &str = r#"
const res = await fetch("/api/settings", { method: "GET" });
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("settings.js", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "raw-http-fetch"),
            "unhinted fetch() should be suppressed by default: {:#?}",
            matches
        );
    }

    #[test]
    fn raw_fetch_without_hint_reported_when_all_http_calls_set() {
        const SRC: &str = r#"const res = await fetch("/api/settings", { method: "GET" });"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let mut o = opts();
        o.all_http_calls = true;
        let matches = scan_js_source("settings.js", SRC, &sigs, &o);
        let hit = matches
            .iter()
            .find(|m| m.library == "raw-http-fetch")
            .expect("expected unhinted fetch to be reported with --all-http-calls");
        assert_eq!(hit.match_strategy, "http-call-only");
        assert!(hit.provider_hint.is_none());
    }

    #[test]
    fn axios_post_with_anthropic_path_detected() {
        const SRC: &str = r#"
await axios.post("https://api.anthropic.com/v1/messages", body, {
  headers: { "x-api-key": key },
});
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("legacy.js", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "raw-http-fetch")
            .expect("no axios match");
        assert_eq!(
            hit.provider_hint.as_deref(),
            Some("Anthropic (Claude Messages API)")
        );
    }

    #[test]
    fn no_false_positives_on_unrelated_code() {
        const SRC: &str = r#"
import React from "react";
function Button({ onClick }) {
  return <button onClick={onClick}>Click</button>;
}
export function sum(a, b) { return a + b; }
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("Button.tsx", SRC, &sigs, &opts());
        assert!(matches.is_empty(), "unexpected matches: {:#?}", matches);
    }

    #[test]
    fn gemini_generate_content_detected() {
        const SRC: &str = r#"
import { GoogleGenerativeAI } from "@google/generative-ai";
const genAI = new GoogleGenerativeAI(key);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });
const result = await model.generateContent(prompt);
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("gemini.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "google-genai" && m.pattern == "generateContent")
            .expect("no gemini match");
        assert_eq!(hit.match_strategy, "call+import");
    }

    // ── ai-sdk useChat().sendMessage vs google-genai chat().sendMessage ──────

    #[test]
    fn ai_sdk_use_chat_send_message_confirmed_via_import() {
        // Real-world case found scanning fastrepl/anarlog: a `sendMessage`
        // callback destructured from `useChat()` (@ai-sdk/react) was, before
        // this dataset entry existed, only ever attributable to google-genai
        // (wrong SDK, same method name). With the import present, this
        // should now resolve to vercel-ai-sdk with high confidence too.
        const SRC: &str = r#"
import { useChat } from "@ai-sdk/react";

function ChatPanel() {
  const { sendMessage } = useChat();
  const onSubmit = () => {
    sendMessage(uiMessage, { chatGroupId: currentGroupId });
  };
}
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("chat-panel.tsx", SRC, &sigs, &opts());

        let ai_sdk_hit = matches
            .iter()
            .find(|m| m.library == "vercel-ai-sdk" && m.pattern == "sendMessage")
            .expect("expected a vercel-ai-sdk sendMessage match");
        assert_eq!(ai_sdk_hit.match_strategy, "call+import");

        // google-genai's ungated sendMessage entry still fires alongside it
        // (by design — see its "kind" note) but only as low-confidence.
        let genai_hit = matches
            .iter()
            .find(|m| m.library == "google-genai" && m.pattern == "sendMessage")
            .expect("expected a google-genai sendMessage candidate too");
        assert_eq!(genai_hit.match_strategy, "call-only");
    }

    #[test]
    fn suffix_pattern_within_same_library_is_not_double_reported() {
        // openai's "completions.create" (legacy) is a textual suffix of its
        // own "chat.completions.create" — must not produce two openai
        // matches for one call site.
        const SRC: &str = r#"
import OpenAI from "openai";
const c = new OpenAI();
c.chat.completions.create({ model: "gpt-4o" });
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("chat.ts", SRC, &sigs, &opts());
        let openai_hits: Vec<_> = matches.iter().filter(|m| m.library == "openai").collect();
        assert_eq!(
            openai_hits.len(),
            1,
            "expected exactly one openai match, got: {:#?}",
            openai_hits
        );
        assert_eq!(openai_hits[0].pattern, "chat.completions.create");
    }

    #[test]
    fn cross_library_ambiguity_on_shared_shape_is_preserved() {
        // openai and groq-sdk deliberately share the same call shape
        // (OpenAI-compatible API) — both should be reported since it's
        // genuinely ambiguous which SDK this is without checking imports.
        const SRC: &str = r#"client.chat.completions.create({ model: "llama3-70b-8192" });"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("groq.js", SRC, &sigs, &opts());
        let libs: Vec<_> = matches.iter().map(|m| m.library.as_str()).collect();
        assert!(
            libs.contains(&"openai"),
            "expected openai candidate: {:#?}",
            matches
        );
        assert!(
            libs.contains(&"groq-sdk"),
            "expected groq-sdk candidate: {:#?}",
            matches
        );
    }

    #[test]
    fn scan_path_walks_directory_and_skips_node_modules() {
        let dir = std::env::temp_dir().join(format!("afg_js_test_{}", std::process::id()));
        let src_dir = dir.join("src");
        let nm_dir = dir.join("node_modules").join("openai");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&nm_dir).unwrap();

        fs::write(
            src_dir.join("chat.ts"),
            r#"import OpenAI from "openai";
const c = new OpenAI();
c.chat.completions.create({});"#,
        )
        .unwrap();
        // Planted in node_modules; must NOT be picked up by default.
        fs::write(
            nm_dir.join("index.js"),
            r#"module.exports.create = function() { return real.chat.completions.create({}); };"#,
        )
        .unwrap();

        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_path(&dir, &sigs, &opts()).unwrap();

        assert!(
            matches.iter().any(|m| m.callsite.file.contains("chat.ts")),
            "expected a match from src/chat.ts: {:#?}",
            matches
        );
        assert!(
            matches
                .iter()
                .all(|m| !m.callsite.file.contains("node_modules")),
            "node_modules should be skipped by default: {:#?}",
            matches
        );

        fs::remove_dir_all(&dir).ok();
    }
}
