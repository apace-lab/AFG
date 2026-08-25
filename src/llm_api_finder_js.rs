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

// A declaration's parameter list is followed (skipping an optional
// `: ReturnType` annotation) directly by a `{` that opens the body -- a call
// expression's closing `)` is never followed by a bare `{` in valid JS/TS
// (that's only legal after a function/method signature). Anchored, so it
// only matches when the `{` (or `: ReturnType {`) comes immediately next.
// See `looks_like_declaration` for how this is used.
static RE_DECL_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?::\s*[^;{}]*)?\{").unwrap());

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

/// Whether the call-shape match whose own opening `(` ends at byte offset
/// `open_paren_end` in `line` is actually a function/method *declaration*
/// rather than an invocation of a cataloged SDK method.
///
/// Real-world case found scanning chroma-core/chroma:
/// `OllamaEmbeddingFunction`'s own `public async generate(texts: string[]) {`
/// method -- Chroma's wrapper implementing its `IEmbeddingFunction`
/// interface, which just happens to share its name with `ollama-js`'s
/// cataloged `generate` method -- was reported as a real `ollama-js` call
/// even though the actual SDK call inside that method body is `.embed(...)`,
/// a different method entirely. Nothing here ever calls the real SDK's
/// `generate`.
///
/// Finds the match's own matching close paren (string/template-literal
/// aware, so a stray `)` inside a default parameter value's string doesn't
/// desync depth tracking) and checks what immediately follows it via
/// `RE_DECL_SUFFIX`. This works uniformly for every declaration shape --
/// `function generate(...)`, class method shorthand (`async generate(...)
/// {`), object method shorthand (`generate(...) {`), getters/setters --
/// without needing to enumerate every possible modifier keyword (`public`,
/// `private`, `static`, `async`, `get`, `set`, ...): none of them change
/// what comes *after* the parameter list.
///
/// Only looks within `line` itself: a multi-line parameter list won't be
/// recognized (no matching close paren is found), so this falls through to
/// `false` ("not a declaration") -- the same recall-over-precision
/// trade-off the rest of this scanner already accepts elsewhere.
fn looks_like_declaration(line: &str, open_paren_end: usize) -> bool {
    let chars: Vec<char> = line[open_paren_end..].chars().collect();
    let mut depth = 1i32;
    let mut in_string: Option<char> = None;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = in_string {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                in_string = Some(c);
                i += 1;
            }
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let rest: String = chars[i + 1..].iter().collect();
                    return RE_DECL_SUFFIX.is_match(rest.trim_start());
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    false // no matching close paren on this line -- can't tell, assume call
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
            if looks_like_declaration(line, *end) {
                continue; // e.g. a class's own method sharing a cataloged SDK method's name
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
        Box::leak(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("datasets")
                .into_boxed_path(),
        )
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
    fn method_declaration_sharing_sdk_pattern_name_is_not_a_call() {
        // Real-world false positive found scanning chroma-core/chroma:
        // OllamaEmbeddingFunction's own `generate` method (implementing its
        // IEmbeddingFunction interface) shares its name with ollama-js's
        // cataloged `generate` call, but the real SDK call inside the body
        // is `.embed(...)` -- a different method. Must not be reported.
        const SRC: &str = r#"
import { Ollama } from "ollama";

export class OllamaEmbeddingFunction {
  public async generate(texts: string[]) {
    return await this.ollamaClient.embed({ input: texts });
  }
}
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("OllamaEmbeddingFunction.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "ollama-js"),
            "method declaration sharing a cataloged SDK pattern name must not be reported as a call: {:#?}",
            matches
        );
    }

    #[test]
    fn plain_function_declaration_sharing_sdk_pattern_name_is_not_a_call() {
        const SRC: &str = r#"
import Cohere from "cohere-ai";
function chat(msg: string) {
  return { role: "user", content: msg };
}
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("helpers.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "cohere-ai"),
            "function declaration sharing a cataloged SDK pattern name must not be reported as a call: {:#?}",
            matches
        );
    }

    #[test]
    fn real_call_immediately_followed_by_block_is_still_detected() {
        // Guard against over-suppression: a real call used as an `if`/`while`
        // condition is also followed by `{`, but not *immediately* after its
        // own matching close paren (the `if`/`while`'s own paren comes
        // first) -- this must still be reported.
        const SRC: &str = r#"
import OpenAI from "openai";
const c = new OpenAI();
if (c.chat.completions.create({ model: "gpt-4o" })) {
  console.log("ok");
}
"#;
        let sigs = load_js_signatures(datasets_path()).unwrap();
        let matches = scan_js_source("guarded.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().any(|m| m.library == "openai"),
            "real call followed by an unrelated block must still be detected: {:#?}",
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
