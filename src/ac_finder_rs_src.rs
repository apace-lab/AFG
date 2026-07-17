//! Companion to `ac_finder` (which scans a RUPTA MIR dump): scans Rust
//! *source text* (.rs files) directly for access-control call sites, no MIR
//! dump or RUPTA toolchain required. Reuses `ac_finder`'s signature catalogue
//! (`AcSignature`/`load_ac_signatures`) since `ac_functions.json` already
//! stores full Rust paths — only the matching strategy changes, because
//! source code uses method-call syntax (`enforcer.enforce(...)`) where MIR
//! uses fully-qualified UFCS (`casbin::CoreApi::enforce(enforcer, ...)`).
//! Same text-scanning philosophy as `ac_finder_js`: regex against a curated
//! catalogue plus an import check used to gate generic method names, and the
//! paren/comma-aware argument scanner is reused almost verbatim from there.

use crate::ac_finder::AcSignature;
use crate::ac_hints::find_ac_hint;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcRsCallSite {
    pub file: String,
    /// Enclosing Rust function, best-effort (last `fn` declaration seen
    /// before the call site — a text-scan heuristic, not scope-aware).
    pub function: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcRsMatch {
    pub library: String,
    pub fn_name: String,
    pub category: String,
    /// "direct" (fully-qualified call) | "method" (`.method(` call, gated by
    /// crate reference) | "short-name" (bare aliased call, gated by crate
    /// reference) | "type-method" (`Type::method(` associated-function call,
    /// gated by crate reference) | "http+path-hint" | "http-call-only"
    pub match_strategy: String,
    pub callsite: AcRsCallSite,
    /// Raw, trimmed text of each top-level call argument, in source order.
    pub parameters: Vec<String>,
    pub raw_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ac_hint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AcRsScanOptions {
    /// Report every `.send(`-shaped call once `reqwest` is referenced in the
    /// file, even when no known access-control REST path suffix is found
    /// nearby. Off by default — `reqwest` is used for plenty of non-AC HTTP
    /// calls.
    pub all_http_calls: bool,
    /// Also scan `target/` (build output — vendored/generated, not the
    /// target's own source). Off by default.
    pub include_target_dir: bool,
}

// ── Regexes ───────────────────────────────────────────────────────────────────

static RE_FN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap()
});

// Naive string-literal capture: good enough for the plain `"..."` case that
// nearly all AC-relevant literals (paths, header names) use. Raw strings
// (`r"..."`, `r#"..."#`) still balance correctly as long as they don't embed
// an unescaped `"`, which none of the AC path hints do.
static RE_STRING_LIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap());

static RE_HTTP_TRIGGER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.send\s*\(").unwrap());

/// How many lines before/after an HTTP trigger to search for a path literal.
const HINT_WINDOW_BEFORE: usize = 6;
const HINT_WINDOW_AFTER: usize = 2;

// ── Argument-list scanning ──────────────────────────────────────────────────────
//
// Same paren/bracket/string-aware scanner as `ac_finder_js`, duplicated to
// keep this module independently testable. One deliberate difference: `'` is
// NOT treated as a string delimiter here. In JS a `'` always opens a string;
// in Rust it's ambiguous between a char literal (`'a'`) and a lifetime
// (`'a`), and a lifetime has no closing quote — treating it as a string
// opener would desync the depth scan for the rest of the file. AC call
// arguments essentially never contain a literal `(` inside a char literal,
// so skipping `'`-awareness is the safer trade-off.

const MAX_ARG_SCAN: usize = 8000;

fn find_matching_close_paren(s: &str, start: usize) -> Option<usize> {
    let chars: Vec<char> = s[start..].chars().collect();
    let mut depth = 1i32;
    let mut in_string = false;
    let mut i = 0usize;
    while i < chars.len() && i < MAX_ARG_SCAN {
        let c = chars[i];
        if in_string {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                i += 1;
            }
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let byte_off: usize = chars[..i].iter().map(|c| c.len_utf8()).sum();
                    return Some(start + byte_off);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Split `s` on top-level commas (depth 0 across `()`/`[]`/`{}`/`<>`,
/// ignoring commas inside string literals). Returns byte-offset `(start,
/// end)` pairs relative to `s`, one per segment (untrimmed).
fn split_top_level_commas(s: &str) -> Vec<(usize, usize)> {
    let chars: Vec<char> = s.chars().collect();
    let mut byte_offsets = Vec::with_capacity(chars.len() + 1);
    let mut acc = 0usize;
    for c in &chars {
        byte_offsets.push(acc);
        acc += c.len_utf8();
    }
    byte_offsets.push(acc);

    let mut segments = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut seg_start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                i += 1;
            }
            '(' | '[' | '{' => {
                depth += 1;
                i += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                i += 1;
            }
            ',' if depth == 0 => {
                segments.push((byte_offsets[seg_start], byte_offsets[i]));
                seg_start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    segments.push((byte_offsets[seg_start], byte_offsets[chars.len()]));
    segments
}

/// Extract the trimmed, top-level argument texts for a call whose `(` sits at
/// byte offset `open_paren` in `content`. Empty argument lists yield `[]`.
fn extract_parameters(content: &str, open_paren: usize) -> Vec<String> {
    let Some(close_paren) = find_matching_close_paren(content, open_paren + 1) else {
        return Vec::new();
    };
    let args_text = &content[open_paren + 1..close_paren];
    split_top_level_commas(args_text)
        .into_iter()
        .map(|(s, e)| args_text[s..e].trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn line_of_byte_offset(content: &str, offset: usize) -> usize {
    content.as_bytes()[..offset].iter().filter(|&&b| b == b'\n').count() + 1
}

// ── Enclosing-function tracking ─────────────────────────────────────────────────

struct FnDecl {
    offset: usize,
    name: String,
}

fn collect_fn_decls(content: &str) -> Vec<FnDecl> {
    RE_FN
        .captures_iter(content)
        .map(|c| FnDecl {
            offset: c.get(0).unwrap().start(),
            name: c[1].to_string(),
        })
        .collect()
}

/// Whether the bare identifier match starting at `offset` is actually the
/// name in a `fn login(...)`-style declaration rather than a call. The
/// "short-name" and "type-method" strategies match on a bare identifier with
/// no dotted/qualified prefix (so a call can be distinguished from a
/// declaration only by what comes *before* it) — the `regex` crate has no
/// lookbehind, so this is a plain post-match text check instead.
fn is_fn_declaration(content: &str, match_start: usize) -> bool {
    let trimmed = content[..match_start].trim_end();
    let Some(prefix) = trimmed.strip_suffix("fn") else {
        return false;
    };
    match prefix.chars().next_back() {
        Some(c) => !c.is_alphanumeric() && c != '_',
        None => true,
    }
}

/// Last `fn` declaration at or before `offset` — a text-scan heuristic (no
/// brace-scope tracking), same trade-off as `ac_finder`'s MIR function
/// tracking and `ac_finder_js`'s route-argument scanning.
fn enclosing_function(decls: &[FnDecl], offset: usize) -> String {
    decls
        .iter()
        .rev()
        .find(|d| d.offset <= offset)
        .map(|d| d.name.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

// ── Import / crate-reference gating ─────────────────────────────────────────────

/// Whether `crate_root` appears to be in use in this file. Checks for an
/// explicit `use`/fully-qualified reference (`crate_root::...`) or
/// `extern crate crate_root`, rather than requiring a `use` statement
/// specifically — a bare qualified call elsewhere in the file (e.g.
/// `jsonwebtoken::decode(...)`) is just as good evidence that a nearby
/// `.decode(` belongs to the same crate.
fn crate_is_referenced(content: &str, crate_root: &str) -> bool {
    if crate_root.is_empty() {
        return false;
    }
    content.contains(&format!("{crate_root}::")) || content.contains(&format!("extern crate {crate_root}"))
}

// ── Matching ──────────────────────────────────────────────────────────────────

struct Matcher {
    strategy: &'static str,
    pattern: Regex,
    requires_import: bool,
}

/// Build source-syntax matchers for one signature. Unlike the MIR scanner
/// (which sees fully-qualified UFCS calls exclusively), real source code
/// mostly calls methods via `.method(` receiver syntax, so that strategy
/// (gated by a crate reference, since method names like `enforce`/`decode`
/// are common words) does the heavy lifting here; "direct" catches the rarer
/// fully-qualified/associated-function call shape, and "type-method" catches
/// the common `use crate::Type; ...; Type::method(...)` associated-function
/// idiom (e.g. `HttpAuthentication::bearer(validator)` after `use
/// actix_web_httpauth::middleware::HttpAuthentication;`).
fn make_source_matchers(sig: &AcSignature) -> Vec<Matcher> {
    let parts: Vec<&str> = sig.fn_name.split("::").collect();
    let method = parts.last().copied().unwrap_or("");

    let mut matchers = Vec::new();

    // 1. Direct fully-qualified call: jsonwebtoken::decode(  or  casbin::CoreApi::enforce(
    let direct_pat = format!(r"{}(?:::<[^>]*>)?\s*\(", regex::escape(&sig.fn_name));
    if let Ok(re) = Regex::new(&direct_pat) {
        matchers.push(Matcher { strategy: "direct", pattern: re, requires_import: false });
    }

    if parts.len() >= 2 {
        // 2. Method-call syntax: enforcer.enforce(...) / token.decode(...)
        let method_pat = format!(r"\.{}(?:::<[^>]*>)?\s*\(", regex::escape(method));
        if let Ok(re) = Regex::new(&method_pat) {
            matchers.push(Matcher { strategy: "method", pattern: re, requires_import: true });
        }

        // 3. Bare short-name free-function call (aliased import): decode(...)
        //    Not preceded by '.' or ':' so it doesn't re-match the direct or
        //    method shapes above.
        let short_pat = format!(r"(?:^|[^.:\w]){}(?:::<[^>]*>)?\s*\(", regex::escape(method));
        if let Ok(re) = Regex::new(&short_pat) {
            matchers.push(Matcher { strategy: "short-name", pattern: re, requires_import: true });
        }
    }

    if parts.len() >= 3 {
        // 4. Type::method(...) after `use crate::path::Type;` — an
        //    associated-function/constructor call on the last two path
        //    segments only. Not preceded by '.' or ':' so a longer
        //    fully-qualified call (already caught by "direct") isn't
        //    double-reported.
        let last_two = parts[parts.len() - 2..].join("::");
        let type_method_pat = format!(r"(?:^|[^.:\w]){}(?:::<[^>]*>)?\s*\(", regex::escape(&last_two));
        if let Ok(re) = Regex::new(&type_method_pat) {
            matchers.push(Matcher { strategy: "type-method", pattern: re, requires_import: true });
        }
    }

    matchers
}

// ── Scanner ───────────────────────────────────────────────────────────────────

/// Scan one file's already-read source text. `file` is the path/label used in
/// reported callsites; it need not exist on disk (useful for tests).
pub fn scan_ac_rs_source(
    file: &str,
    content: &str,
    sigs: &[AcSignature],
    opts: &AcRsScanOptions,
) -> Vec<AcRsMatch> {
    let fn_decls = collect_fn_decls(content);
    let lines: Vec<&str> = content.lines().collect();
    let literals: Vec<Vec<String>> = lines
        .iter()
        .map(|line| RE_STRING_LIT.captures_iter(line).map(|c| c[1].to_string()).collect())
        .collect();

    let mut matches = Vec::new();

    // ── SDK/library call sites ──
    for sig in sigs.iter().filter(|s| s.library != "raw-http-authz") {
        let crate_root = sig.fn_name.split("::").next().unwrap_or("");
        for m in make_source_matchers(sig) {
            if m.requires_import && !crate_is_referenced(content, crate_root) {
                continue;
            }
            for mat in m.pattern.find_iter(content) {
                if matches!(m.strategy, "short-name" | "type-method") && is_fn_declaration(content, mat.start()) {
                    continue; // e.g. `fn login(...)` shadowing AuthSession::login as a bare identifier
                }
                let open_paren = mat.end() - 1;
                let lineno = line_of_byte_offset(content, mat.start());
                let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                matches.push(AcRsMatch {
                    library: sig.library.clone(),
                    fn_name: sig.fn_name.clone(),
                    category: sig.category.clone(),
                    match_strategy: m.strategy.to_string(),
                    callsite: AcRsCallSite {
                        file: file.to_string(),
                        function: enclosing_function(&fn_decls, mat.start()),
                        line: lineno,
                    },
                    parameters: extract_parameters(content, open_paren),
                    raw_line,
                    ac_hint: None,
                });
            }
        }
    }

    // ── raw HTTP calls to an access-control service ──
    if let Some(http_sig) = sigs.iter().find(|s| s.library == "raw-http-authz") {
        if crate_is_referenced(content, "reqwest") {
            for mat in RE_HTTP_TRIGGER.find_iter(content) {
                let open_paren = mat.end() - 1;
                let lineno = line_of_byte_offset(content, mat.start());
                let idx = lineno - 1;
                let start = idx.saturating_sub(HINT_WINDOW_BEFORE);
                let end = (idx + HINT_WINDOW_AFTER + 1).min(literals.len());
                let nearby: Vec<&String> = literals[start..end].iter().flatten().collect();
                let hint = find_ac_hint(&nearby);

                if hint.is_none() && !opts.all_http_calls {
                    continue;
                }
                let raw_line = lines.get(idx).map(|l| l.trim().to_string()).unwrap_or_default();
                matches.push(AcRsMatch {
                    library: http_sig.library.clone(),
                    fn_name: http_sig.fn_name.clone(),
                    category: http_sig.category.clone(),
                    match_strategy: if hint.is_some() { "http+path-hint" } else { "http-call-only" }.to_string(),
                    callsite: AcRsCallSite {
                        file: file.to_string(),
                        function: enclosing_function(&fn_decls, mat.start()),
                        line: lineno,
                    },
                    parameters: extract_parameters(content, open_paren),
                    raw_line,
                    ac_hint: hint,
                });
            }
        }
    }

    // Signatures load from a `HashMap`-backed JSON object, so iterating them
    // (the outer loop above) has no stable order across runs — unlike the
    // MIR/JS scanners, which iterate MIR lines / source lines directly and
    // are naturally position-ordered. Sort by line so output is
    // deterministic and reads top-to-bottom like the file itself.
    matches.sort_by(|a, b| a.callsite.line.cmp(&b.callsite.line).then_with(|| a.fn_name.cmp(&b.fn_name)));

    matches
}

const SCAN_EXTENSIONS: &[&str] = &["rs"];

/// Walk `root` (a file or a directory) and scan every `.rs` source file found
/// under it.
pub fn scan_ac_rs_path(
    root: &Path,
    sigs: &[AcSignature],
    opts: &AcRsScanOptions,
) -> Result<Vec<AcRsMatch>, Box<dyn Error>> {
    if root.is_file() {
        let content = fs::read_to_string(root)?;
        return Ok(scan_ac_rs_source(&root.display().to_string(), &content, sigs, opts));
    }

    let mut matches = Vec::new();
    let walker = walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        if !e.file_type().is_dir() {
            return true;
        }
        let name = e.file_name().to_string_lossy();
        if name == ".git" {
            return false;
        }
        if name == "target" && !opts.include_target_dir {
            return false;
        }
        true
    });

    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("");
        if !SCAN_EXTENSIONS.contains(&ext) {
            continue;
        }
        let content = match fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue, // skip unreadable/non-UTF8 files rather than aborting the whole scan
        };
        matches.extend(scan_ac_rs_source(&entry.path().display().to_string(), &content, sigs, opts));
    }

    Ok(matches)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ac_finder::load_ac_signatures;

    fn datasets_path() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").leak()
    }

    fn opts() -> AcRsScanOptions {
        AcRsScanOptions::default()
    }

    #[test]
    fn detects_jsonwebtoken_decode_direct_call() {
        const SRC: &str = r#"
fn verify_token(token: &str, key: &DecodingKey, validation: &Validation) -> Result<TokenData<Claims>, Error> {
    jsonwebtoken::decode::<Claims>(token, key, validation)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("auth.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "jsonwebtoken" && m.fn_name == "jsonwebtoken::decode")
            .expect("no jsonwebtoken::decode match");
        assert_eq!(hit.match_strategy, "direct");
        assert_eq!(hit.category, "authentication");
        assert_eq!(hit.callsite.function, "verify_token");
        assert_eq!(hit.parameters, vec!["token", "key", "validation"]);
    }

    #[test]
    fn detects_casbin_enforce_via_method_syntax_gated_by_import() {
        const SRC: &str = r#"
use casbin::CoreApi;

fn check_access(enforcer: &Enforcer, sub: &str, obj: &str, act: &str) -> bool {
    enforcer.enforce((sub, obj, act)).unwrap_or(false)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("authz.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "casbin-rs" && m.match_strategy == "method")
            .expect("no casbin method match");
        assert_eq!(hit.category, "policy-enforcement");
        assert_eq!(hit.callsite.function, "check_access");
        assert_eq!(hit.parameters, vec!["(sub, obj, act)"]);
    }

    #[test]
    fn detects_type_method_associated_function_call() {
        const SRC: &str = r#"
use actix_web_httpauth::middleware::HttpAuthentication;

fn build_auth_middleware() -> HttpAuthentication<Claims, fn() -> ()> {
    HttpAuthentication::bearer(validator)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("mw.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "actix-web-httpauth" && m.match_strategy == "type-method")
            .expect("no HttpAuthentication::bearer type-method match");
        assert_eq!(hit.category, "authentication");
        assert_eq!(hit.callsite.function, "build_auth_middleware");
        assert_eq!(hit.parameters, vec!["validator"]);
    }

    #[test]
    fn type_method_suppressed_without_crate_reference() {
        const SRC: &str = r#"
fn build_something() -> LocalAuth {
    HttpAuthentication::bearer(validator)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("mw.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "actix-web-httpauth"),
            "unexpected match without a crate reference: {:#?}",
            matches
        );
    }

    #[test]
    fn method_call_suppressed_without_crate_reference() {
        // "enforce" is a common enough word that without any casbin
        // reference in the file, this must not fire.
        const SRC: &str = r#"
fn check_access(policy: &LocalPolicy) -> bool {
    policy.enforce()
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("misc.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "casbin-rs"),
            "unexpected casbin match without crate reference: {:#?}",
            matches
        );
    }

    #[test]
    fn multiline_call_arguments_are_captured() {
        const SRC: &str = r#"
fn check(enforcer: &casbin::Enforcer) -> bool {
    casbin::CoreApi::enforce(
        enforcer,
        ("alice", "data1", "read"),
    ).unwrap_or(false)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("multiline.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "casbin-rs" && m.match_strategy == "direct")
            .expect("no direct casbin match");
        assert_eq!(hit.parameters, vec!["enforcer", r#"("alice", "data1", "read")"#]);
    }

    #[test]
    fn raw_http_authz_gets_ac_hint_from_nearby_literal() {
        const SRC: &str = r#"
fn introspect_token(client: &reqwest::Client, base: &str, token: &str) -> reqwest::Result<reqwest::Response> {
    let url = format!("{}/introspect", base);
    client.post(url).form(&[("token", token)]).send()
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("client.rs", SRC, &sigs, &opts());
        let hit = matches.iter().find(|m| m.library == "raw-http-authz").expect("no raw-http-authz match");
        assert_eq!(hit.match_strategy, "http+path-hint");
        assert_eq!(hit.ac_hint.as_deref(), Some("OAuth2 token introspection (RFC 7662)"));
    }

    #[test]
    fn raw_http_without_hint_is_suppressed_by_default() {
        const SRC: &str = r#"
fn ping(client: &reqwest::Client) -> reqwest::Result<reqwest::Response> {
    client.get("https://example.com/health").send()
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("health.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "raw-http-authz"),
            "unhinted .send() should be suppressed by default: {:#?}",
            matches
        );
    }

    #[test]
    fn no_send_without_reqwest_reference() {
        const SRC: &str = r#"
fn forward(tx: std::sync::mpsc::Sender<i32>) {
    tx.send(1).unwrap();
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("chan.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "raw-http-authz"),
            "mpsc::Sender::send should not be mistaken for reqwest without a reqwest reference: {:#?}",
            matches
        );
    }

    #[test]
    fn fn_declaration_sharing_a_signature_name_is_not_a_call() {
        // `login` is also axum_login::AuthSession::login's short name; a
        // function *declared* `fn login(...)` must not be reported as a
        // call to it.
        const SRC: &str = r#"
use axum_login::AuthnBackend;

async fn login(backend: &MyAuthBackend, creds: Credentials) -> Result<Option<User>, BackendError> {
    backend.authenticate(creds).await
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("auth.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.fn_name != "axum_login::AuthSession::login"),
            "fn declaration was mistaken for a call to AuthSession::login: {:#?}",
            matches
        );
        // The real call inside the body must still be found.
        assert!(
            matches.iter().any(|m| m.fn_name == "axum_login::AuthnBackend::authenticate"),
            "expected the real authenticate() call to still be detected: {:#?}",
            matches
        );
    }

    #[test]
    fn no_false_positives_on_unrelated_code() {
        const SRC: &str = r#"
use std::collections::HashMap;

fn build_map() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("a".to_string(), "b".to_string());
    m
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("map.rs", SRC, &sigs, &opts());
        assert!(matches.is_empty(), "unexpected matches: {:#?}", matches);
    }

    #[test]
    fn scan_path_walks_directory_and_skips_target() {
        let dir = std::env::temp_dir().join(format!("afg_ac_rs_src_test_{}", std::process::id()));
        let src_dir = dir.join("src");
        let target_dir = dir.join("target").join("debug");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&target_dir).unwrap();

        fs::write(
            src_dir.join("auth.rs"),
            r#"
fn verify(token: &str, key: &jsonwebtoken::DecodingKey, v: &jsonwebtoken::Validation) {
    let _ = jsonwebtoken::decode::<()>(token, key, v);
}
"#,
        )
        .unwrap();
        fs::write(
            target_dir.join("build_artifact.rs"),
            r#"fn generated() { let _ = jsonwebtoken::decode::<()>("x", y, z); }"#,
        )
        .unwrap();

        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_path(&dir, &sigs, &opts()).unwrap();

        assert!(
            matches.iter().any(|m| m.callsite.file.contains("auth.rs")),
            "expected a match from src/auth.rs: {:#?}",
            matches
        );
        assert!(
            matches.iter().all(|m| !m.callsite.file.contains("target")),
            "target/ should be skipped by default: {:#?}",
            matches
        );

        fs::remove_dir_all(&dir).ok();
    }
}
