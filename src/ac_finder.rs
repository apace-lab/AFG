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
use std::collections::{HashMap, HashSet};
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
    /// How this signature's shape was established -- "general-knowledge" |
    /// "docs.rs" | "manual" | "ambient" | "unspecified" (missing from the
    /// catalog entry). Surfaced on every match (see `AcMatch::verified_via`
    /// and its siblings) so a consumer can triage/filter speculative matches
    /// from verified ones without cross-referencing the catalog by hand.
    pub verified_via: String,
    /// "call" (default -- a function/method invocation) | "attribute" (a
    /// `#[pattern(...)]` proc-macro attribute -- see
    /// `ac_finder_rs_src::scan_attribute_guards`). Attribute-kind signatures
    /// are skipped by the MIR/LLVM-IR scanners entirely: attribute macros
    /// expand away before codegen, so there's no realistic callee text for
    /// either to match.
    pub kind: String,
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
    /// Copied from the matching `AcSignature::verified_via` -- how
    /// trustworthy this signature's shape is, for triaging matches without
    /// cross-referencing the catalog by hand.
    pub verified_via: String,
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
            let verified_via = entry
                .get("verified_via")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified")
                .to_string();
            let kind = entry.get("kind").and_then(|v| v.as_str()).unwrap_or("call").to_string();
            sigs.push(AcSignature {
                library: lib_name.clone(),
                fn_name,
                category,
                return_type,
                parameter_type,
                verified_via,
                kind,
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

// ── Crate-reference gating (short-name strategy only) ───────────────────────
//
// Unlike `ac_finder_rs_src`, this scanner has no import statements to check --
// MIR has no `use`. But the "short-name" strategy (last two path segments,
// unanchored -- e.g. `Enforcer::enforce(`) is just as capable of colliding
// with an unrelated local type/method of the same name here as it is in
// source text, and had no mitigation at all before this: any MIR callee text
// containing that shape matched regardless of whether the signature's crate
// was actually used anywhere in the dump. This closes that gap the same way
// `ac_finder_rs_src::crate_is_referenced` does -- requiring the crate root to
// appear as a `root::` path segment somewhere else in the dump -- just
// computed once as a `HashSet` up front (rather than re-scanning the whole
// file's text per candidate) since a MIR dump can be very large.
static RE_PATH_ROOT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)::").unwrap());

fn collect_referenced_roots(content: &str) -> HashSet<String> {
    RE_PATH_ROOT.captures_iter(content).map(|c| c[1].to_string()).collect()
}

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
    // "axum-extractors", "actix-web-extractors", "outbound-credential-header",
    // and "inbound-credential-header" are find_ac_points_src-only (see
    // src/AC_FINDER.md's Supported libraries table): they need source-level
    // inspection this scanner's call-shape matching can't safely replicate.
    // The two extractor libraries' trait-impl patterns don't have a
    // realistic MIR call shape at all (harmless if left in), but
    // `reqwest::RequestBuilder::header`/`HeaderMap::get` genuinely do --
    // every `.header("Content-Type", ...)` / `some_map.get("id")` call would
    // match just as readily as an `.header("Authorization", ...)` /
    // `headers.get("Authorization")` one, since MIR call-shape matching has
    // no way to inspect which header name was actually passed, or (for
    // `.get`) that the receiver was a `HeaderMap` at all rather than any
    // other type with a `get` method. Excluding the whole library keeps the
    // "find_ac_points_src only" claim in the docs actually true rather than
    // just usually-harmless-by-luck.
    let sig_matchers: Vec<(&AcSignature, Vec<Matcher>)> = sigs
        .iter()
        .filter(|sig| {
            sig.library != "axum-extractors"
                && sig.library != "actix-web-extractors"
                && sig.library != "outbound-credential-header"
                && sig.library != "inbound-credential-header"
                && sig.kind != "attribute" // proc-macro attributes expand away before MIR -- no realistic callee text here
        })
        .map(|sig| (sig, make_matchers(sig)))
        .collect();

    let referenced_roots = collect_referenced_roots(mir_content);

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
                    if matcher.strategy == "short-name" {
                        let crate_root = sig.fn_name.split("::").next().unwrap_or("");
                        if !referenced_roots.contains(crate_root) {
                            continue; // no corroborating reference to this crate anywhere in the dump
                        }
                    }
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
                        verified_via: sig.verified_via.clone(),
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
        Box::leak(Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").into_boxed_path())
    }

    fn sig(library: &str, fn_name: &str, category: &str) -> AcSignature {
        AcSignature {
            library: library.to_string(),
            fn_name: fn_name.to_string(),
            category: category.to_string(),
            return_type: String::new(),
            parameter_type: vec![],
            verified_via: "general-knowledge".to_string(),
            kind: "call".to_string(),
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
        assert_eq!(matches[0].verified_via, "general-knowledge");
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
    fn outbound_credential_header_is_not_matched_in_mir() {
        // Regression guard: `reqwest::RequestBuilder::header` is
        // find_ac_points_src-only (its match strategy there inspects the
        // actual header-name argument via AUTH_HEADER_NAMES). MIR call-shape
        // matching alone can't distinguish `.header("Authorization", ...)`
        // from `.header("Content-Type", ...)` -- both compile to the same
        // callee shape -- so this scanner must not load that signature at
        // all, or every plain header-setting call would be mislabeled
        // "authentication".
        const MIR: &str = r#"
[FuncId(1) - "my_app::ping"]
fn ping() -> () {
    let _0: ();
    let _1: reqwest::RequestBuilder;
    let _2: reqwest::RequestBuilder;

    bb0: {
        _2 = reqwest::RequestBuilder::header::<&str, &str>(move _1, const "Content-Type", const "application/json") -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).expect("load_ac_signatures");
        let matches = scan_ac_mir(MIR, &sigs);
        assert!(
            matches.iter().all(|m| m.library != "outbound-credential-header"),
            "Content-Type header call was mislabeled as a credential header: {:#?}",
            matches
        );
    }

    #[test]
    fn short_name_match_suppressed_without_crate_reference() {
        // Regression test: "short-name" (last two path segments, unanchored
        // -- "CoreApi::enforce" for casbin::CoreApi::enforce) must not fire
        // when nothing else in the dump corroborates that the signature's
        // crate is actually in play -- an unrelated local `CoreApi::enforce`
        // sharing casbin's method name must not be misreported as a casbin
        // call.
        const MIR: &str = r#"
[FuncId(1) - "my_app::check_local_policy"]
fn check_local_policy() -> () {
    let _0: ();
    let _1: LocalPolicy;
    let _2: bool;

    bb0: {
        _2 = CoreApi::enforce(move _1) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("casbin-rs", "casbin::CoreApi::enforce", "policy-enforcement")];
        let matches = scan_ac_mir(MIR, &sigs);
        assert!(
            matches.is_empty(),
            "unrelated CoreApi::enforce should not match casbin without a crate reference: {:#?}",
            matches
        );
    }

    #[test]
    fn short_name_match_allowed_with_crate_reference() {
        // Same shape as above, but this time the dump genuinely references
        // `casbin::` elsewhere -- real corroborating evidence -- so the
        // short-name match should still fire.
        const MIR: &str = r#"
[FuncId(1) - "my_app::check_access"]
fn check_access() -> () {
    let _0: ();
    let _1: casbin::Enforcer;
    let _2: bool;

    bb0: {
        _2 = CoreApi::enforce(move _1) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("casbin-rs", "casbin::CoreApi::enforce", "policy-enforcement")];
        let matches = scan_ac_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1, "expected the short-name match to fire: {:#?}", matches);
        assert_eq!(matches[0].match_strategy, "short-name");
    }

    #[test]
    fn strip_turbofish_matches_llm_finder_behavior() {
        assert_eq!(
            strip_turbofish("jsonwebtoken::decode::<Claims>("),
            "jsonwebtoken::decode("
        );
    }
}
