//! Companion to `llm_api_finder`: scans a Rust program's RUPTA MIR dump for
//! calls into known access-control crates/functions (authentication,
//! authorization, and policy-enforcement entry points) instead of LLM SDK
//! calls. Same text-scanning philosophy — regex against a curated signature
//! catalogue, not a full parse/typecheck — and the same three-strategy match
//! rules (direct / angle-bracket / short-name), reused verbatim from
//! `llm_api_finder`.

use crate::ac_hints::find_ac_hint;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcSignature {
    pub library: String,
    pub fn_name: String,
    pub category: String,
    pub return_type: String,
    pub parameter_type: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcCallSite {
    pub func_id: String,
    pub function: String,
    pub basic_block: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcMatch {
    pub library: String,
    pub fn_name: String,
    pub category: String,
    pub match_strategy: String,
    pub callsite: AcCallSite,
    pub raw_line: String,
    /// Best-effort access-control service guess for `raw-http-authz` matches,
    /// derived from REST path suffixes seen in string literals earlier in the
    /// same function (see `find_ac_hint`). `None` when no known suffix was
    /// found, or for matches from libraries whose name already identifies
    /// the mechanism.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ac_hint: Option<String>,
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load all access-control signatures from `datasets_path/ac_functions.json`.
/// Re-parsed on every call so users can update the file without recompiling.
pub fn load_ac_signatures(datasets_path: &Path) -> Result<Vec<AcSignature>, Box<dyn std::error::Error>> {
    let json_path = datasets_path.join("ac_functions.json");
    let content = fs::read_to_string(&json_path)
        .map_err(|e| format!("cannot read {}: {}", json_path.display(), e))?;
    let data: HashMap<String, serde_json::Value> = serde_json::from_str(&content)?;

    let mut sigs = Vec::new();
    for (lib_name, entries) in &data {
        if lib_name.starts_with('_') {
            continue;
        }
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for entry in entries {
            let fn_name = entry["fn_name"].as_str().unwrap_or("").to_string();
            if fn_name.is_empty() {
                continue;
            }
            let category = entry
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified")
                .to_string();
            let return_type = entry
                .get("return_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let parameter_type = entry
                .get("parameter_type")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            sigs.push(AcSignature {
                library: lib_name.clone(),
                fn_name,
                category,
                return_type,
                parameter_type,
            });
        }
    }
    Ok(sigs)
}

// ── Matching ──────────────────────────────────────────────────────────────────

struct Matcher {
    strategy: &'static str,
    pattern: Regex,
}

/// Build per-signature regex matchers (same three strategies as
/// `llm_api_finder::make_matchers`).
fn make_matchers(sig: &AcSignature) -> Vec<Matcher> {
    let parts: Vec<&str> = sig.fn_name.split("::").collect();
    let method = parts.last().copied().unwrap_or("");
    let struct_path = if parts.len() > 1 {
        parts[..parts.len() - 1].join("::")
    } else {
        String::new()
    };

    let mut matchers = Vec::new();

    // 1. Direct:  jsonwebtoken::decode<...>(
    let direct_pat = format!(r"{}(?:<[^(]*)?\s*\(", regex::escape(&sig.fn_name));
    if let Ok(re) = Regex::new(&direct_pat) {
        matchers.push(Matcher { strategy: "direct", pattern: re });
    }

    // 2. Angle-bracket:  <casbin::Enforcer ...>::enforce<...>(
    if !struct_path.is_empty() {
        let ab_pat = format!(
            r"<\s*{}[^>]*>\s*::\s*{}(?:<[^(]*)?\s*\(",
            regex::escape(&struct_path),
            regex::escape(method)
        );
        if let Ok(re) = Regex::new(&ab_pat) {
            matchers.push(Matcher { strategy: "angle-bracket", pattern: re });
        }
    }

    // 3. Short-name:  Enforcer::enforce(  (last two path segments — lower confidence)
    if parts.len() >= 2 {
        let last_two = parts[parts.len() - 2..].join("::");
        let short_pat = format!(r"{}\s*\(", regex::escape(&last_two));
        if let Ok(re) = Regex::new(&short_pat) {
            matchers.push(Matcher { strategy: "short-name", pattern: re });
        }
    }

    matchers
}

// ── MIR line patterns ─────────────────────────────────────────────────────────

static RE_FUNC_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\[FuncId\((\d+)\)\s*-\s*"([^"]+)"\]"#).unwrap()
});

static RE_BB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+(bb\w+):\s*\{").unwrap());

// Captures callee: optional "dest = " prefix, then everything up to "("
static RE_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+(?:_\d+\s*=\s*)?(?P<callee>[^=(][^(]*)\(").unwrap());

// Captures every quoted string literal on a line, e.g. `const "..."` or a
// format-string argument to `alloc::fmt::format`.
static RE_STRING_LIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap());

// ── Scanner ───────────────────────────────────────────────────────────────────

/// Remove `::<...>` turbofish segments from a callee path, including nested
/// generics. See `llm_api_finder::strip_turbofish` for the rationale — same
/// implementation, duplicated to keep this module independently testable.
fn strip_turbofish(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ':' && chars.get(i + 1) == Some(&':') && chars.get(i + 2) == Some(&'<') {
            let mut depth = 1;
            let mut j = i + 3;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '<' => depth += 1,
                    '>' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            i = j;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Scan `mir_content` for calls matching any of `sigs`.
/// Returns one `AcMatch` per unique (callsite, signature) pair found.
pub fn scan_ac_mir(mir_content: &str, sigs: &[AcSignature]) -> Vec<AcMatch> {
    let sig_matchers: Vec<(&AcSignature, Vec<Matcher>)> =
        sigs.iter().map(|sig| (sig, make_matchers(sig))).collect();

    let mut matches = Vec::new();
    let mut current_func_id = String::from("unknown");
    let mut current_func_name = String::from("unknown");
    let mut current_bb = String::from("unknown");
    // String literals seen so far in the current function, oldest first —
    // feeds find_ac_hint for raw-http-authz matches. Reset on new function.
    let mut func_string_literals: Vec<String> = Vec::new();

    for (lineno, line) in mir_content.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        if let Some(caps) = RE_FUNC_HEADER.captures(line) {
            current_func_id = format!("FuncId({})", &caps[1]);
            current_func_name = caps[2].to_string();
            current_bb = String::from("unknown");
            func_string_literals.clear();
            continue;
        }
        if let Some(caps) = RE_BB.captures(line) {
            current_bb = caps[1].to_string();
            continue;
        }
        for lit in RE_STRING_LIT.captures_iter(line) {
            func_string_literals.push(lit[1].to_string());
        }
        let Some(caps) = RE_CALL.captures(line) else {
            continue;
        };

        // Re-append "(" so that patterns ending with \( can match
        let callee_raw = format!("{}(", caps["callee"].trim());
        let callee_raw = strip_turbofish(&callee_raw);

        'sig: for (sig, matchers) in &sig_matchers {
            for matcher in matchers {
                if matcher.pattern.is_match(&callee_raw) {
                    let ac_hint = if sig.library == "raw-http-authz" {
                        find_ac_hint(&func_string_literals)
                    } else {
                        None
                    };
                    matches.push(AcMatch {
                        library: sig.library.clone(),
                        fn_name: sig.fn_name.clone(),
                        category: sig.category.clone(),
                        match_strategy: matcher.strategy.to_string(),
                        callsite: AcCallSite {
                            func_id: current_func_id.clone(),
                            function: current_func_name.clone(),
                            basic_block: current_bb.clone(),
                            line: lineno,
                        },
                        raw_line: line.trim().to_string(),
                        ac_hint,
                    });
                    break 'sig;
                }
            }
        }
    }

    matches
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn datasets_path() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").leak()
    }

    fn sig(library: &str, fn_name: &str, category: &str) -> AcSignature {
        AcSignature {
            library: library.to_string(),
            fn_name: fn_name.to_string(),
            category: category.to_string(),
            return_type: String::new(),
            parameter_type: vec![],
        }
    }

    #[test]
    fn loads_all_ac_libraries() {
        let sigs = load_ac_signatures(datasets_path()).expect("load_ac_signatures failed");
        assert!(!sigs.is_empty(), "expected at least one signature");
        let libs: Vec<_> = sigs.iter().map(|s| s.library.as_str()).collect();
        for expected in &[
            "actix-web-httpauth",
            "actix-web-grants",
            "jsonwebtoken",
            "casbin-rs",
            "oso",
            "biscuit-auth",
            "raw-http-authz",
        ] {
            assert!(libs.contains(expected), "library '{expected}' missing from loaded signatures");
        }
    }

    #[test]
    fn detects_jsonwebtoken_decode() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::verify_token"]
fn verify_token() -> () {
    let _0: ();
    let _1: alloc::string::String;
    let _2: jsonwebtoken::DecodingKey;
    let _3: jsonwebtoken::Validation;
    let _4: std::result::Result<jsonwebtoken::TokenData<Claims>, jsonwebtoken::errors::Error>;

    bb0: {
        _4 = jsonwebtoken::decode::<Claims>(move _1, move _2, move _3) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("jsonwebtoken", "jsonwebtoken::decode", "authentication")];
        let matches = scan_ac_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1, "missed jsonwebtoken::decode: {:#?}", matches);
        assert_eq!(matches[0].category, "authentication");
    }

    #[test]
    fn detects_casbin_enforce() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::check_access"]
fn check_access() -> () {
    let _0: ();
    let _1: casbin::Enforcer;
    let _2: std::result::Result<bool, casbin::Error>;

    bb0: {
        _2 = casbin::CoreApi::enforce(move _1, const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("casbin-rs", "casbin::CoreApi::enforce", "policy-enforcement")];
        let matches = scan_ac_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1, "missed casbin::CoreApi::enforce: {:#?}", matches);
    }

    #[test]
    fn raw_http_authz_gets_ac_hint_from_nearby_literal() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::introspect_token"]
fn introspect_token() -> () {
    let _0: ();
    let _1: alloc::string::String;
    let _2: reqwest::RequestBuilder;
    let _3: std::result::Result<reqwest::Response, reqwest::Error>;

    bb0: {
        _1 = alloc::fmt::format(const "{}/introspect") -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = reqwest::Client::post::<alloc::string::String>(move _4, move _1) -> [return: bb2, unwind continue];
    }
    bb2: {
        _3 = reqwest::RequestBuilder::send(move _2) -> [return: bb3, unwind continue];
    }
    bb3: { return; }
}
"#;
        let sigs = vec![sig("raw-http-authz", "reqwest::RequestBuilder::send", "raw-http")];
        let matches = scan_ac_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].ac_hint.as_deref(),
            Some("OAuth2 token introspection (RFC 7662)")
        );
    }

    #[test]
    fn no_false_positives_on_unrelated_calls() {
        const MIR: &str = r#"
[FuncId(1) - "demo::main"]
fn main() -> () {
    bb0: {
        _1 = std::collections::HashMap::<String, String>::new() -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).expect("load_ac_signatures");
        let matches = scan_ac_mir(MIR, &sigs);
        assert!(matches.is_empty(), "false positives detected: {:#?}", matches);
    }

    #[test]
    fn strip_turbofish_matches_llm_finder_behavior() {
        assert_eq!(
            strip_turbofish("jsonwebtoken::decode::<Claims>("),
            "jsonwebtoken::decode("
        );
    }
}
