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
use crate::ac_hints::{find_ac_hint, find_auth_header_hint, find_auth_query_param_hint};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// gated by crate reference) | "short-name-alias" (bare call to a
    /// `use path::fn as alias;`-renamed free function) | "type-method-alias"
    /// (`Alias::method(` call through a `use path::Type as Alias;`-renamed
    /// type) | "attribute" (`#[pattern(...)]` proc-macro guard, gated by
    /// crate reference) | "http+path-hint" | "http-call-only"
    pub match_strategy: String,
    pub callsite: AcRsCallSite,
    /// Raw, trimmed text of each top-level call argument, in source order.
    pub parameters: Vec<String>,
    pub raw_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ac_hint: Option<String>,
    /// Copied from the matching `AcSignature::verified_via` -- how
    /// trustworthy this signature's shape is, for triaging matches without
    /// cross-referencing the catalog by hand.
    pub verified_via: String,
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
    /// Custom auth-extractor types (e.g. a hand-rolled `impl
    /// FromRequestParts for Jwt`) already confirmed elsewhere -- typically
    /// populated by `scan_ac_rs_path`'s first pass over the whole tree, so
    /// its second pass can recognize a handler parameter like
    /// `current_user: Jwt` even in a file that never defines `Jwt` itself.
    /// Empty by default: a standalone `scan_ac_rs_source` call (as used
    /// directly by this module's tests) only sees extractor types defined
    /// within that same call's `content`.
    pub known_auth_extractors: Vec<KnownAuthExtractor>,
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

// `.header("Authorization", ...)` / `.header("x-api-key", ...)` etc. --
// outbound credential attachment, gated on the actual header name (via
// AUTH_HEADER_NAMES) rather than crate-reference alone, since ".header(" is
// too generic a call shape to gate any other way (`.header("Content-Type",
// ...)` is just as common and not access-control-relevant at all).
static RE_HEADER_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\.header\s*\(\s*"([^"]+)""#).unwrap());

// `headers.insert("Authorization", ...)` / `header_map.insert("api-key", ...)`
// -- the non-reqwest analog of RE_HEADER_CALL above, for HTTP clients that
// build a header map by hand (opentelemetry-otlp, hyper, a hand-rolled
// client, ...) instead of chaining `RequestBuilder::header`. `.insert(` is
// far more generic a method name than `.header(` (HashMap/BTreeMap/Vec/DB
// rows/...), so the header-name gate alone isn't enough here -- the
// receiver identifier is additionally required to contain "header" (see the
// call site below), which the capture group makes cheap to check.
static RE_HEADER_MAP_INSERT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\.insert\s*\(\s*"([^"]+)""#).unwrap());

// `.query(&[("key", api_key), ...])` -- the URL-query-string sibling of
// RE_HEADER_CALL, for APIs (Gemini Developer API's `?key=`, ...) that take
// their credential as a query parameter instead of a header. Only finds the
// call site itself; unlike `.header(...)` a single `.query(...)` call
// commonly carries a whole param list/map in one argument, so the scan below
// pulls the matched call's full argument text (via find_matching_close_paren)
// and checks every string literal in it against AUTH_QUERY_PARAM_NAMES,
// rather than this regex trying to capture just the credential one.
static RE_QUERY_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.query\s*\(").unwrap());

// `.header(name, value)` where `name` is a variable/field, not a string
// literal -- RE_HEADER_CALL structurally can't see this shape (it requires a
// `"..."` immediately after the paren), e.g. bionic-gpt's
// tool-runtime/builtin_tools/openapi_tool_adapter.rs, which builds a
// per-integration `(String, String)` header pair from a config field
// (`self.auth_header_name`) in one function and applies it via a generic
// `for (name, value) in headers { request = request.header(name, value); }`
// in another. Since the header's real name can't be read from the call site
// itself, this is gated on a whole-file auth-flavored signal instead (see
// DYNAMIC_HEADER_AUTH_SIGNAL_KEYWORDS) rather than the literal-name match the
// static case uses -- lower precision, so every hit is reported as a
// "verify manually" candidate via its ac_hint.
static RE_HEADER_CALL_DYNAMIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.header\s*\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*,").unwrap());

// `headers.get("Authorization")` / `parts.headers.get("x-api-key")` --
// inbound analog of RE_HEADER_MAP_INSERT: a hand-rolled check of an
// *incoming* request's headers, rather than a structured extractor. Same
// "receiver identifier must contain 'header'" gate as RE_HEADER_MAP_INSERT,
// for the same reason (`.get(` is even more generic a method name than
// `.insert(` -- HashMap/Option/Vec/BTreeMap/... all have one).
static RE_HEADER_GET_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\.get\s*\(\s*"([^"]+)""#).unwrap());

// `req.headers().get("Authorization")` -- actix-web's `HttpRequest::headers()`
// returns the map via a method call rather than a field, so the receiver
// immediately before `.get(` is `)`, not an identifier; RE_HEADER_GET_FIELD
// can't see this shape, hence a second regex anchored on the explicit
// `.headers().get(...)` chain instead of a receiver-name gate.
static RE_HEADER_GET_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.headers\s*\(\s*\)\s*\.get\s*\(\s*"([^"]+)""#).unwrap());

/// How many lines before/after an HTTP trigger to search for a path literal.
const HINT_WINDOW_BEFORE: usize = 6;
const HINT_WINDOW_AFTER: usize = 2;

// axum's `impl FromRequestParts<S> for MyAuthedUser { ... }` is the idiomatic
// way apps that don't pull in axum-login/actix-identity hand-roll a custom
// auth guard (decode a bearer/JWT/session header inside
// `from_request_parts`). It's a trait *definition* site, not a call, so it
// needs its own regex + body scan rather than the direct/method/short-name/
// type-method matchers above, which only look for `name(` call shapes.
//
// The trailing `\b` matters: without it this would also match as a prefix of
// `impl FromRequestParts<S> for X` (axum's *other*, more common extractor
// trait), since "FromRequest" is a strict prefix of "FromRequestParts" and
// both sides of that boundary are word characters, so `\b` alone correctly
// refuses to match there.
static RE_ACTIX_FR_IMPL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"impl(?:<[^>{]*>)?\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*FromRequest\b(?:<[^>{]*>)?\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
        .unwrap()
});

static RE_AXUM_FRP_IMPL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"impl(?:<[^>{]*>)?\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*FromRequestParts(?:<[^>{]*>)?\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
        .unwrap()
});

// `TypedHeader<Authorization<Bearer>>` / `TypedHeader<Authorization<Basic>>`
// (axum-extra + the `headers` crate) is the idiomatic way to pull a
// bearer/basic auth header out of a request as a handler parameter -- a
// type-usage site, not a call either.
static RE_AXUM_AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Authorization\s*<\s*(Bearer|Basic)\s*>").unwrap());

/// Case-insensitive signals that a `FromRequestParts`/`FromRequest` impl is
/// plausibly an auth guard rather than some other extractor (`ConnectInfo`,
/// `OriginalUri`, a request-id extractor, ...). Not exhaustive -- same
/// heuristic trade-off as `ac_hints::AC_PATH_HINTS`, checked against the
/// impl block body plus its header line. Shared between axum's
/// `FromRequestParts` and actix-web's `FromRequest` -- both are the same
/// "hand-rolled auth guard" idiom, just on different traits/crates.
const EXTRACTOR_AUTH_SIGNAL_KEYWORDS: &[&str] = &[
    "authoriz",
    "bearer",
    "jwt",
    "session",
    "cookie",
    "credential",
    "x-forwarded",
    "x_forwarded",
    "permission",
    "rbac",
];

fn find_extractor_auth_signal(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    EXTRACTOR_AUTH_SIGNAL_KEYWORDS.iter().find(|kw| lower.contains(*kw)).copied()
}

/// Case-insensitive signals used to gate `RE_HEADER_CALL_DYNAMIC` (a
/// `.header(name, value)` call whose header name is a variable, not a
/// literal). Checked against the *whole file*, not a line window -- unlike
/// `EXTRACTOR_AUTH_SIGNAL_KEYWORDS`, the code that determines a dynamic
/// header's real name (e.g. a `build_auth_header`-style method reading a
/// config field) is routinely tens of lines away from -- and can be textually
/// *before* -- the generic passthrough call that actually invokes
/// `.header(name, value)`, so a fixed-line window like `HINT_WINDOW_*` would
/// often miss it. A whole-file gate trades precision (any dynamic
/// `.header(...)` call anywhere in a file that happens to also mention
/// "bearer" elsewhere gets flagged) for recall on this specific shape; every
/// match this produces is marked "verify manually" via its `ac_hint`.
const DYNAMIC_HEADER_AUTH_SIGNAL_KEYWORDS: &[&str] =
    &["bearer", "authoriz", "api_key", "api-key", "apikey", "access_token", "auth_header", "auth_token", "credential"];

fn find_dynamic_header_auth_signal(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    DYNAMIC_HEADER_AUTH_SIGNAL_KEYWORDS.iter().find(|kw| lower.contains(*kw)).copied()
}

/// A custom auth-guard type confirmed via `impl FromRequestParts`/
/// `FromRequest` (see `detect_local_auth_extractors`) -- either in the same
/// file or, when scanning a whole tree via `scan_ac_rs_path`, discovered in a
/// different file entirely. Used by `scan_extractor_param_usage` to find the
/// handler-parameter usage sites of that type (`current_user: Jwt`), which is
/// almost always in a different function -- usually a different file -- than
/// the `impl` itself.
#[derive(Debug, Clone)]
pub struct KnownAuthExtractor {
    pub type_name: String,
    pub library: String,
    pub fn_name: String,
    pub verified_via: String,
}

/// Byte offset of the matching `}` for the `{` at `content[open_brace]`,
/// scanning forward. String-aware (so a `format!("{}", x)` inside the body
/// doesn't desync the depth count) but not comment-aware, same trade-off as
/// `find_matching_close_paren`.
fn find_matching_close_brace(content: &str, open_brace: usize) -> Option<usize> {
    let chars: Vec<char> = content[open_brace..].chars().collect();
    let mut depth = 0i32;
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
            '{' => {
                depth += 1;
                i += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let byte_off: usize = chars[..=i].iter().map(|c| c.len_utf8()).sum();
                    return Some(open_brace + byte_off);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

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

/// First `fn` declaration at or after `offset` -- used for attribute
/// guards (`#[has_permissions(...)]`), which sit *above* the function they
/// decorate rather than inside its body, so `enclosing_function`'s
/// last-seen-before-offset logic would attribute the match to the *previous*
/// function instead. Same text-scan-heuristic trade-off as
/// `enclosing_function`: it doesn't verify there's nothing but other
/// attributes/doc comments between the match and the `fn`, so a
/// misapplied attribute (not actually followed by a function) would be
/// attributed to whatever function happens to come next in the file.
fn following_function(decls: &[FnDecl], offset: usize) -> String {
    decls
        .iter()
        .find(|d| d.offset >= offset)
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

/// Whether `crate_root` is named in a `use` statement (`use crate_root;`,
/// `use crate_root::...;`, `use crate_root as alias;`, with any visibility
/// prefix -- `pub use`, `pub(crate) use`, ...) or an `extern crate
/// crate_root` declaration anywhere in `content`. Boundary-checked so
/// `use axum_extra_foo::Bar;` doesn't count as a reference to `axum_extra`.
/// Line-anchored, not a full parser -- same heuristic philosophy as the rest
/// of this file.
fn has_use_import(content: &str, crate_root: &str) -> bool {
    if crate_root.is_empty() {
        return false;
    }
    let use_needle = format!("use {crate_root}");
    let has_use = content.lines().any(|line| {
        let Some(pos) = line.find(&use_needle) else {
            return false;
        };
        matches!(line[pos + use_needle.len()..].chars().next(), None | Some(':') | Some(';') | Some(' '))
    });
    has_use || content.contains(&format!("extern crate {crate_root}"))
}

/// How many lines before/after a candidate match to search for a nearby
/// fully-qualified reference to the gating crate, in `crate_is_referenced_near`.
const CRATE_REFERENCE_WINDOW: usize = 60;

/// Scope-aware version of `crate_is_referenced`, used only by the generic
/// per-signature SDK matchers (the `method`/`short-name`/`type-method`
/// strategies) below -- the one place a whole-file gate caused a real false
/// positive: two unrelated crates, each legitimately referenced somewhere in
/// a large multi-purpose file, sharing a method name (e.g. both
/// actix-web-httpauth's `BearerAuth::token` and axum-extra's `Bearer::token`)
/// could cross-contaminate a `.token(` match anywhere in the file once
/// *either* crate was referenced *anywhere*, regardless of distance.
///
/// A `use`/`extern crate` import is still file-wide evidence -- Rust imports
/// genuinely apply to the whole file (module nesting aside, which this tool
/// doesn't track anywhere, before or after this change). Only the *fallback*
/// evidence -- a bare fully-qualified reference elsewhere, for import-free,
/// always-fully-qualified coding styles -- is windowed to
/// `CRATE_REFERENCE_WINDOW` lines around the match, rather than the whole
/// file.
fn crate_is_referenced_near(content: &str, lines: &[&str], match_line_idx: usize, crate_root: &str) -> bool {
    if crate_root.is_empty() {
        return false;
    }
    if has_use_import(content, crate_root) {
        return true;
    }
    let start = match_line_idx.saturating_sub(CRATE_REFERENCE_WINDOW);
    let end = (match_line_idx + CRATE_REFERENCE_WINDOW + 1).min(lines.len());
    let needle = format!("{crate_root}::");
    lines[start..end].iter().any(|l| l.contains(&needle))
}

// ── `use ... as alias` resolution ───────────────────────────────────────────
//
// `use jsonwebtoken::decode as jwt_decode;` renames a symbol at the call
// site: nothing about `jwt_decode(...)` contains the catalogue's `decode`
// text in a position the "short-name" matcher's boundary check accepts (the
// preceding char is `_`, a word char), so without resolving the alias back
// to its real path, the call was silently missed -- not a false positive,
// a false negative with no prior mitigation. This is a single-hop, per-file,
// regex-based resolver covering the two common `use`-aliasing shapes --
// `use a::b::c as d;` and `use a::b::{c as d, ...};` -- not the general Rust
// `use`-tree grammar (arbitrarily nested groups, multi-level re-export
// chains). See "Known blind spots" in AC_FINDER.md.

static RE_USE_ALIAS_SIMPLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\buse\s+((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)+)([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*;").unwrap()
});

static RE_USE_ALIAS_GROUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\buse\s+((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)+)\{([^{}]*)\}").unwrap()
});

static RE_GROUP_ITEM_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap());

/// Map local alias identifier -> the fully-qualified path it renames, for
/// every `use ... as alias;` import found in `content` (already
/// comment-stripped). Whitespace inside the path prefix (`a :: b ::`) is
/// normalized away so the result lines up with catalogue paths, which never
/// contain spaces.
fn collect_use_aliases(content: &str) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for caps in RE_USE_ALIAS_SIMPLE.captures_iter(content) {
        let prefix: String = caps[1].chars().filter(|c| !c.is_whitespace()).collect();
        let orig = &caps[2];
        let alias = caps[3].to_string();
        aliases.insert(alias, format!("{prefix}{orig}"));
    }
    for caps in RE_USE_ALIAS_GROUP.captures_iter(content) {
        let prefix: String = caps[1].chars().filter(|c| !c.is_whitespace()).collect();
        for item in caps[2].split(',') {
            if let Some(icaps) = RE_GROUP_ITEM_ALIAS.captures(item) {
                let orig = &icaps[1];
                let alias = icaps[2].to_string();
                aliases.insert(alias, format!("{prefix}{orig}"));
            }
        }
    }
    aliases
}

// ── Comment stripping ────────────────────────────────────────────────────────

/// Replace `//`/`///`/`//!` line comments and (possibly nested) `/* */` block
/// comments with spaces, leaving every newline and every other character --
/// including string-literal contents, since `raw-http-authz`'s `ac_hint`
/// scanning needs those intact -- untouched. All matching/gating in
/// `scan_ac_rs_source` runs against this cleaned text rather than the
/// original, so a call-shaped example inside an explanatory doc comment (or a
/// stray unbalanced `(`/`{` in a comment, which used to desync the
/// paren/brace depth-scanners below) can no longer produce a false match.
/// Line numbers computed against the result line up exactly with the
/// original, since replacing characters with spaces never adds or removes a
/// `\n`.
///
/// Same simplified string-tracking model as `find_matching_close_paren`
/// elsewhere in this file, and the same documented trade-off: doesn't
/// special-case raw strings (`r#"..."#`) or char literals/lifetimes (`'a`),
/// so a `//` or `/*` inside one of those could in principle still be
/// misread as starting a comment. Not a new gap -- the same trade-off this
/// file already accepts for paren/brace matching.
fn strip_comments(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut i = 0usize;
    let mut in_string = false;

    while i < chars.len() {
        let c = chars[i];

        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }

        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1i32;
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < chars.len() && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }

        out.push(c);
        i += 1;
    }

    out
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

/// Scan for `#[pattern(...)]` proc-macro attribute guards (`kind: "attribute"`
/// catalog entries -- currently actix-web-grants' `has_permissions`/
/// `has_roles`/`has_any_role`/`has_any_permission`). These have a real
/// `pattern(...)` text shape, so the same boundary-anchored regex approach
/// as the `short-name` strategy works (`#[` is a non-word char, satisfying
/// the boundary), but they need two things the ordinary call-shape loop
/// doesn't do: gate on crate reference the same way generic method names do
/// (these macro names are distinctive enough to rarely collide, but nothing
/// here relies on that), and attribute the match to the function the
/// attribute decorates -- the *next* `fn`, not the last one seen, since the
/// attribute sits above its target rather than inside it (see
/// `following_function`).
fn scan_attribute_guards(
    file: &str,
    cleaned: &str,
    cleaned_lines: &[&str],
    lines: &[&str],
    fn_decls: &[FnDecl],
    sigs: &[AcSignature],
) -> Vec<AcRsMatch> {
    let mut out = Vec::new();
    for sig in sigs.iter().filter(|s| s.kind == "attribute") {
        let crate_root = sig.fn_name.split("::").next().unwrap_or("");
        let method = sig.fn_name.rsplit("::").next().unwrap_or("");
        let pat = format!(r"#\s*\[\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*{}\s*\(", regex::escape(method));
        let Ok(re) = Regex::new(&pat) else { continue };
        for mat in re.find_iter(cleaned) {
            let lineno = line_of_byte_offset(cleaned, mat.start());
            if !crate_is_referenced_near(cleaned, cleaned_lines, lineno - 1, crate_root) {
                continue;
            }
            let open_paren = mat.end() - 1;
            let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
            out.push(AcRsMatch {
                library: sig.library.clone(),
                fn_name: sig.fn_name.clone(),
                category: sig.category.clone(),
                match_strategy: "attribute".to_string(),
                callsite: AcRsCallSite {
                    file: file.to_string(),
                    function: following_function(fn_decls, mat.start()),
                    line: lineno,
                },
                parameters: extract_parameters(cleaned, open_paren),
                raw_line,
                ac_hint: None,
                verified_via: sig.verified_via.clone(),
            });
        }
    }
    out
}

/// Scan for `impl TRAIT for TypeName { ... }` auth-guard definitions
/// matching `pattern`, gated on `crate_gate` being referenced *and* an
/// auth-flavored signal in the impl body/header line (see
/// `find_extractor_auth_signal`). Shared by axum's `FromRequestParts` and
/// actix-web's `FromRequest` -- same idiom, different trait/crate.
/// `trait_display` names the trait in the reported `callsite.function`;
/// `extractor_label` names the framework in the `ac_hint` text.
#[allow(clippy::too_many_arguments)]
fn scan_trait_impl_extractor(
    file: &str,
    cleaned: &str,
    lines: &[&str],
    pattern: &Regex,
    crate_gate: &str,
    library: &str,
    fn_name: &str,
    trait_display: &str,
    extractor_label: &str,
    verified_via: &str,
) -> Vec<AcRsMatch> {
    let mut out = Vec::new();
    if !crate_is_referenced(cleaned, crate_gate) {
        return out;
    }
    for caps in pattern.captures_iter(cleaned) {
        let mat = caps.get(0).unwrap();
        let type_name = caps.get(1).map(|g| g.as_str()).unwrap_or("");
        let header_line = cleaned[mat.start()..].lines().next().unwrap_or("");
        // Body := the impl block's braces. If they can't be found (e.g.
        // truncated/malformed source), fall back to scanning just the header
        // line itself for a signal.
        let body_text = cleaned[mat.end()..]
            .find('{')
            .and_then(|rel_open| {
                let open_brace = mat.end() + rel_open;
                find_matching_close_brace(cleaned, open_brace).map(|close| &cleaned[open_brace..=close])
            })
            .unwrap_or(header_line);

        let Some(signal) = find_extractor_auth_signal(body_text).or_else(|| find_extractor_auth_signal(header_line)) else {
            continue; // no auth-flavored signal -- likely a non-auth extractor (ConnectInfo, OriginalUri, ...)
        };

        let lineno = line_of_byte_offset(cleaned, mat.start());
        let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
        out.push(AcRsMatch {
            library: library.to_string(),
            fn_name: fn_name.to_string(),
            category: "authentication".to_string(),
            match_strategy: "trait-impl".to_string(),
            callsite: AcRsCallSite {
                file: file.to_string(),
                function: format!("impl {trait_display} for {type_name}"),
                line: lineno,
            },
            parameters: vec![type_name.to_string()],
            raw_line,
            ac_hint: Some(format!("custom {extractor_label} auth extractor (signal: \"{signal}\")")),
            verified_via: verified_via.to_string(),
        });
    }
    out
}

/// Run both `scan_trait_impl_extractor` passes (axum's `FromRequestParts`,
/// actix-web's `FromRequest`) against one file's already-cleaned content.
/// Factored out of `scan_ac_rs_source` so `scan_ac_rs_path` can call just
/// this (cheap: comment-stripping plus two regex passes) in its first,
/// tree-wide pass to build the `KnownAuthExtractor` registry, without
/// running the full scan pipeline twice per file.
fn detect_local_auth_extractors(file: &str, cleaned: &str, lines: &[&str], sigs: &[AcSignature]) -> Vec<AcRsMatch> {
    let mut out = Vec::new();
    if let Some(frp_sig) = sigs.iter().find(|s| s.library == "axum-extractors" && s.fn_name.contains("FromRequestParts")) {
        out.extend(scan_trait_impl_extractor(
            file,
            cleaned,
            lines,
            &RE_AXUM_FRP_IMPL,
            "axum",
            &frp_sig.library,
            &frp_sig.fn_name,
            "FromRequestParts",
            "axum",
            &frp_sig.verified_via,
        ));
    }
    if let Some(fr_sig) = sigs.iter().find(|s| s.library == "actix-web-extractors" && s.fn_name.contains("FromRequest")) {
        out.extend(scan_trait_impl_extractor(
            file,
            cleaned,
            lines,
            &RE_ACTIX_FR_IMPL,
            "actix_web",
            &fr_sig.library,
            &fr_sig.fn_name,
            "FromRequest",
            "actix-web",
            &fr_sig.verified_via,
        ));
    }
    out
}

/// Scan for handler-parameter usage of a *known* custom auth-extractor type
/// (`current_user: Jwt`), given types already confirmed by
/// `detect_local_auth_extractors` (same file) or `AcRsScanOptions::
/// known_auth_extractors` (elsewhere in the tree). Matches `ident: TypeName`
/// immediately after a `(` or `,` -- i.e. a function-parameter-list
/// position -- which also accepts a struct field of that type (`user: Jwt,`
/// inside a `struct { ... }`); that's a deliberate, documented trade-off
/// (see AC_FINDER.md's Known blind spots) rather than trying to verify the
/// enclosing item is actually a `fn`, since this file has no real Rust
/// parser to lean on.
fn scan_extractor_param_usage(file: &str, cleaned: &str, lines: &[&str], fn_decls: &[FnDecl], known: &[KnownAuthExtractor]) -> Vec<AcRsMatch> {
    let mut out = Vec::new();
    for extractor in known {
        if extractor.type_name.is_empty() {
            continue;
        }
        let pat = format!(r"[(,]\s*(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:\s*{}\b", regex::escape(&extractor.type_name));
        let Ok(re) = Regex::new(&pat) else { continue };
        for mat in re.find_iter(cleaned) {
            let lineno = line_of_byte_offset(cleaned, mat.start());
            let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
            out.push(AcRsMatch {
                library: extractor.library.clone(),
                fn_name: extractor.fn_name.clone(),
                category: "authentication".to_string(),
                match_strategy: "extractor-param-usage".to_string(),
                callsite: AcRsCallSite {
                    file: file.to_string(),
                    function: enclosing_function(fn_decls, mat.start()),
                    line: lineno,
                },
                parameters: vec![extractor.type_name.clone()],
                raw_line,
                ac_hint: Some(format!(
                    "handler parameter typed as custom auth-extractor `{}` (defined via {})",
                    extractor.type_name, extractor.fn_name
                )),
                verified_via: extractor.verified_via.clone(),
            });
        }
    }
    out
}

/// Scan one file's already-read source text. `file` is the path/label used in
/// reported callsites; it need not exist on disk (useful for tests).
pub fn scan_ac_rs_source(
    file: &str,
    content: &str,
    sigs: &[AcSignature],
    opts: &AcRsScanOptions,
) -> Vec<AcRsMatch> {
    // All matching/gating below runs against `cleaned` (comments blanked to
    // spaces), not `content` -- see `strip_comments`. `content`/`lines` stay
    // around purely so `raw_line` shows the real, unmodified source text.
    let cleaned = strip_comments(content);
    let fn_decls = collect_fn_decls(&cleaned);
    let use_aliases = collect_use_aliases(&cleaned);
    let lines: Vec<&str> = content.lines().collect();
    let cleaned_lines: Vec<&str> = cleaned.lines().collect();
    let literals: Vec<Vec<String>> = cleaned_lines
        .iter()
        .map(|line| RE_STRING_LIT.captures_iter(line).map(|c| c[1].to_string()).collect())
        .collect();

    let mut matches = Vec::new();

    // ── SDK/library call sites ──
    // `reqwest::RequestBuilder::header`, `HeaderMap::insert`,
    // `reqwest::RequestBuilder::query`, and `HeaderMap::get` are excluded
    // here: "header"/"insert"/"query"/"get" are too generic a method name to
    // safely call/import-gate like the rest of the catalogue (they'd fire on
    // every `.header("Content-Type", ...)` / arbitrary map `.insert(...)` /
    // every unrelated `.query(...)` / every `Option`/`HashMap`/`Vec` `.get(...)`
    // too), so they get their own name-aware scans below instead.
    for sig in sigs.iter().filter(|s| {
        s.library != "raw-http-authz"
            && s.library != "axum-extractors"
            && s.library != "actix-web-extractors"
            && s.fn_name != "reqwest::RequestBuilder::header"
            && s.fn_name != "HeaderMap::insert"
            && s.fn_name != "reqwest::RequestBuilder::query"
            && s.fn_name != "HeaderMap::get"
            && s.kind != "attribute" // handled separately by scan_attribute_guards -- needs its own enclosing-function logic
    }) {
        let crate_root = sig.fn_name.split("::").next().unwrap_or("");
        for m in make_source_matchers(sig) {
            for mat in m.pattern.find_iter(&cleaned) {
                let lineno = line_of_byte_offset(&cleaned, mat.start());
                if m.requires_import && !crate_is_referenced_near(&cleaned, &cleaned_lines, lineno - 1, crate_root) {
                    continue;
                }
                if matches!(m.strategy, "short-name" | "type-method") && is_fn_declaration(&cleaned, mat.start()) {
                    continue; // e.g. `fn login(...)` shadowing AuthSession::login as a bare identifier
                }
                let open_paren = mat.end() - 1;
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
                    parameters: extract_parameters(&cleaned, open_paren),
                    raw_line,
                    ac_hint: None,
                    verified_via: sig.verified_via.clone(),
                });
            }
        }

        // ── alias-resolved calls (`use path::name as alias;`) ──
        // A `use ... as alias` import is itself the strongest possible
        // import evidence -- stronger than `crate_is_referenced_near`'s
        // nearby-reference fallback -- so an alias-resolved match is never
        // gated further.
        let sig_parts: Vec<&str> = sig.fn_name.split("::").collect();
        for (alias, resolved) in &use_aliases {
            let is_free_fn_alias = *resolved == sig.fn_name;
            let is_type_alias = sig_parts.len() >= 2 && *resolved == sig_parts[..sig_parts.len() - 1].join("::");
            if !is_free_fn_alias && !is_type_alias {
                continue;
            }
            let strategy = if is_free_fn_alias { "short-name-alias" } else { "type-method-alias" };
            let callee_text = if is_free_fn_alias {
                alias.clone()
            } else {
                format!("{alias}::{}", sig_parts.last().copied().unwrap_or(""))
            };
            let pat = format!(r"(?:^|[^.:\w]){}(?:::<[^>]*>)?\s*\(", regex::escape(&callee_text));
            let Ok(re) = Regex::new(&pat) else { continue };
            for mat in re.find_iter(&cleaned) {
                if is_fn_declaration(&cleaned, mat.start()) {
                    continue; // e.g. `fn jwt_decode(...)` shadowing the aliased call as a bare identifier
                }
                let lineno = line_of_byte_offset(&cleaned, mat.start());
                let open_paren = mat.end() - 1;
                let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                matches.push(AcRsMatch {
                    library: sig.library.clone(),
                    fn_name: sig.fn_name.clone(),
                    category: sig.category.clone(),
                    match_strategy: strategy.to_string(),
                    callsite: AcRsCallSite {
                        file: file.to_string(),
                        function: enclosing_function(&fn_decls, mat.start()),
                        line: lineno,
                    },
                    parameters: extract_parameters(&cleaned, open_paren),
                    raw_line,
                    ac_hint: None,
                    verified_via: sig.verified_via.clone(),
                });
            }
        }
    }

    // ── raw HTTP calls to an access-control service ──
    if let Some(http_sig) = sigs.iter().find(|s| s.library == "raw-http-authz") {
        if crate_is_referenced(&cleaned, "reqwest") {
            for mat in RE_HTTP_TRIGGER.find_iter(&cleaned) {
                let open_paren = mat.end() - 1;
                let lineno = line_of_byte_offset(&cleaned, mat.start());
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
                    parameters: extract_parameters(&cleaned, open_paren),
                    raw_line,
                    ac_hint: hint,
                    verified_via: http_sig.verified_via.clone(),
                });
            }
        }
    }

    // ── outbound credential-header attachment (`.header("Authorization", ...)`) ──
    if let Some(header_sig) = sigs.iter().find(|s| s.fn_name == "reqwest::RequestBuilder::header") {
        if crate_is_referenced(&cleaned, "reqwest") {
            for caps in RE_HEADER_CALL.captures_iter(&cleaned) {
                let mat = caps.get(0).unwrap();
                let header_name = caps.get(1).map(|g| g.as_str()).unwrap_or("");
                let Some(desc) = find_auth_header_hint(header_name) else {
                    continue; // not a known credential header (Content-Type, Accept, ...)
                };
                // Locate the call's own '(' directly rather than computing an
                // offset from the match end -- the gap between "header" and
                // "(" (and between "(" and the opening quote) is `\s*`, so
                // its width isn't fixed.
                let open_paren = mat.start() + cleaned[mat.start()..mat.end()].find('(').unwrap();
                let lineno = line_of_byte_offset(&cleaned, mat.start());
                let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                matches.push(AcRsMatch {
                    library: header_sig.library.clone(),
                    fn_name: format!("{}(\"{header_name}\")", header_sig.fn_name),
                    category: header_sig.category.clone(),
                    match_strategy: "http-auth-header".to_string(),
                    callsite: AcRsCallSite {
                        file: file.to_string(),
                        function: enclosing_function(&fn_decls, mat.start()),
                        line: lineno,
                    },
                    parameters: extract_parameters(&cleaned, open_paren),
                    raw_line,
                    ac_hint: Some(desc.to_string()),
                    verified_via: header_sig.verified_via.clone(),
                });
            }

            // ── same call shape, but the header *name* is a variable/field
            // rather than a literal (RE_HEADER_CALL can't see this at all) --
            // gated on a whole-file auth signal instead of the literal-name
            // match, since the code that determines the variable's real
            // value is routinely in a different function. See
            // RE_HEADER_CALL_DYNAMIC's doc comment. ──
            if let Some(signal) = find_dynamic_header_auth_signal(&cleaned) {
                for caps in RE_HEADER_CALL_DYNAMIC.captures_iter(&cleaned) {
                    let mat = caps.get(0).unwrap();
                    let header_expr = caps.get(1).map(|g| g.as_str()).unwrap_or("");
                    let open_paren = mat.start() + cleaned[mat.start()..mat.end()].find('(').unwrap();
                    let lineno = line_of_byte_offset(&cleaned, mat.start());
                    let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                    matches.push(AcRsMatch {
                        library: header_sig.library.clone(),
                        fn_name: format!("{}({header_expr})", header_sig.fn_name),
                        category: header_sig.category.clone(),
                        match_strategy: "http-auth-header-dynamic".to_string(),
                        callsite: AcRsCallSite {
                            file: file.to_string(),
                            function: enclosing_function(&fn_decls, mat.start()),
                            line: lineno,
                        },
                        parameters: extract_parameters(&cleaned, open_paren),
                        raw_line,
                        ac_hint: Some(format!(
                            "dynamic header name (\"{header_expr}\") in a file with an auth-flavored signal (\"{signal}\") -- verify manually"
                        )),
                        verified_via: header_sig.verified_via.clone(),
                    });
                }
            }
        }
    }

    // ── inbound credential-header check (`headers.get("Authorization")` /
    // `req.headers().get("x-api-key")`) -- a hand-rolled check of an
    // *incoming* request's headers, as opposed to a structured extractor
    // (`impl FromRequestParts`, `TypedHeader<Authorization<Bearer>>`) ──
    if let Some(get_sig) = sigs.iter().find(|s| s.fn_name == "HeaderMap::get") {
        for caps in RE_HEADER_GET_FIELD.captures_iter(&cleaned) {
            let mat = caps.get(0).unwrap();
            let receiver = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            if !receiver.to_lowercase().contains("header") {
                continue; // too generic a method name to gate on the header-name literal alone
            }
            let header_name = caps.get(2).map(|g| g.as_str()).unwrap_or("");
            // `find_auth_header_hint` is used purely as the "is this a known
            // credential header name" gate here -- its description text is
            // written for the outbound direction ("...attached to an
            // outbound request"), so it isn't reused verbatim in `ac_hint`
            // below.
            if find_auth_header_hint(header_name).is_none() {
                continue; // not a known credential header (Content-Type, Accept, ...)
            }
            let open_paren = mat.start() + cleaned[mat.start()..mat.end()].find('(').unwrap();
            let lineno = line_of_byte_offset(&cleaned, mat.start());
            let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
            matches.push(AcRsMatch {
                library: get_sig.library.clone(),
                fn_name: format!("{receiver}.get(\"{header_name}\")"),
                category: get_sig.category.clone(),
                match_strategy: "inbound-auth-header".to_string(),
                callsite: AcRsCallSite {
                    file: file.to_string(),
                    function: enclosing_function(&fn_decls, mat.start()),
                    line: lineno,
                },
                parameters: extract_parameters(&cleaned, open_paren),
                raw_line,
                ac_hint: Some(format!("credential read from an inbound \"{header_name}\" header")),
                verified_via: get_sig.verified_via.clone(),
            });
        }
        for caps in RE_HEADER_GET_METHOD.captures_iter(&cleaned) {
            let mat = caps.get(0).unwrap();
            let header_name = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            if find_auth_header_hint(header_name).is_none() {
                continue; // not a known credential header (Content-Type, Accept, ...)
            }
            // Two calls chained (`.headers()` then `.get(`) -- locate the
            // *second* '(' (the one belonging to `.get(`), not the first.
            let headers_call_paren = mat.start() + cleaned[mat.start()..mat.end()].find('(').unwrap();
            let open_paren = headers_call_paren + 1 + cleaned[headers_call_paren + 1..mat.end()].find('(').unwrap();
            let lineno = line_of_byte_offset(&cleaned, mat.start());
            let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
            matches.push(AcRsMatch {
                library: get_sig.library.clone(),
                fn_name: format!("HttpRequest::headers().get(\"{header_name}\")"),
                category: get_sig.category.clone(),
                match_strategy: "inbound-auth-header".to_string(),
                callsite: AcRsCallSite {
                    file: file.to_string(),
                    function: enclosing_function(&fn_decls, mat.start()),
                    line: lineno,
                },
                parameters: extract_parameters(&cleaned, open_paren),
                raw_line,
                ac_hint: Some(format!("credential read from an inbound \"{header_name}\" header")),
                verified_via: get_sig.verified_via.clone(),
            });
        }
    }

    // ── outbound credential-header attachment via a hand-built header map
    // (`headers.insert("Authorization", ...)`) -- the non-reqwest analog of
    // the `.header(...)` scan above ──
    if let Some(insert_sig) = sigs.iter().find(|s| s.fn_name == "HeaderMap::insert") {
        for caps in RE_HEADER_MAP_INSERT.captures_iter(&cleaned) {
            let mat = caps.get(0).unwrap();
            let receiver = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            if !receiver.to_lowercase().contains("header") {
                continue; // too generic a method name to gate on the header-name literal alone
            }
            let header_name = caps.get(2).map(|g| g.as_str()).unwrap_or("");
            let Some(desc) = find_auth_header_hint(header_name) else {
                continue; // not a known credential header (Content-Type, Accept, ...)
            };
            let open_paren = mat.start() + cleaned[mat.start()..mat.end()].find('(').unwrap();
            let lineno = line_of_byte_offset(&cleaned, mat.start());
            let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
            matches.push(AcRsMatch {
                library: insert_sig.library.clone(),
                fn_name: format!("{receiver}.insert(\"{header_name}\")"),
                category: insert_sig.category.clone(),
                match_strategy: "header-map-insert".to_string(),
                callsite: AcRsCallSite {
                    file: file.to_string(),
                    function: enclosing_function(&fn_decls, mat.start()),
                    line: lineno,
                },
                parameters: extract_parameters(&cleaned, open_paren),
                raw_line,
                ac_hint: Some(desc.to_string()),
                verified_via: insert_sig.verified_via.clone(),
            });
        }
    }

    // ── outbound credential attachment via a URL query parameter
    // (`.query(&[("key", api_key), ...])`) -- the query-string sibling of
    // the `.header(...)` scan above ──
    if let Some(query_sig) = sigs.iter().find(|s| s.fn_name == "reqwest::RequestBuilder::query") {
        if crate_is_referenced(&cleaned, "reqwest") {
            for mat in RE_QUERY_CALL.find_iter(&cleaned) {
                let open_paren = mat.end() - 1;
                let Some(close_paren) = find_matching_close_paren(&cleaned, open_paren + 1) else {
                    continue;
                };
                let args_text = &cleaned[open_paren + 1..close_paren];
                for caps in RE_STRING_LIT.captures_iter(args_text) {
                    let lit = caps.get(1).unwrap();
                    let Some(desc) = find_auth_query_param_hint(lit.as_str()) else {
                        continue; // not a known credential query param (model, page_size, ...)
                    };
                    let abs_offset = open_paren + 1 + lit.start();
                    let lineno = line_of_byte_offset(&cleaned, abs_offset);
                    let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                    matches.push(AcRsMatch {
                        library: query_sig.library.clone(),
                        fn_name: format!("{}(\"{}\")", query_sig.fn_name, lit.as_str()),
                        category: query_sig.category.clone(),
                        match_strategy: "query-param-auth".to_string(),
                        callsite: AcRsCallSite {
                            file: file.to_string(),
                            function: enclosing_function(&fn_decls, mat.start()),
                            line: lineno,
                        },
                        parameters: extract_parameters(&cleaned, open_paren),
                        raw_line,
                        ac_hint: Some(desc.to_string()),
                        verified_via: query_sig.verified_via.clone(),
                    });
                }
            }
        }
    }

    // ── custom hand-rolled auth extractors (`impl FromRequestParts`/`FromRequest` for MyAuthedUser`) ──
    let local_extractor_matches = detect_local_auth_extractors(file, &cleaned, &lines, sigs);
    matches.extend(local_extractor_matches.iter().cloned());

    // ── handler-parameter usage of a known custom auth-extractor type
    // (`current_user: Jwt`) -- the other half of the pattern above. The
    // `impl FromRequestParts for Jwt` block only appears once per type, but
    // the real access-control gate fires at every handler that takes `Jwt`
    // as a parameter, almost always in a different file. Known types come
    // from this same file's own `impl` (just collected above) plus whatever
    // `scan_ac_rs_path`'s first pass found elsewhere in the tree (see
    // `AcRsScanOptions::known_auth_extractors`).
    let mut known_extractors = opts.known_auth_extractors.clone();
    known_extractors.extend(local_extractor_matches.iter().filter(|m| m.match_strategy == "trait-impl").map(|m| KnownAuthExtractor {
        type_name: m.parameters.first().cloned().unwrap_or_default(),
        library: m.library.clone(),
        fn_name: m.fn_name.clone(),
        verified_via: m.verified_via.clone(),
    }));
    {
        let mut seen = std::collections::HashSet::new();
        known_extractors.retain(|e| seen.insert(e.type_name.clone()));
    }
    matches.extend(scan_extractor_param_usage(file, &cleaned, &lines, &fn_decls, &known_extractors));

    // ── axum-extra typed bearer/basic auth header extraction ──
    if let Some(hdr_sig) = sigs.iter().find(|s| s.library == "axum-extractors" && s.fn_name.contains("headers::Authorization")) {
        if crate_is_referenced(&cleaned, "axum_extra") || crate_is_referenced(&cleaned, "headers") {
            for caps in RE_AXUM_AUTH_HEADER.captures_iter(&cleaned) {
                let mat = caps.get(0).unwrap();
                let scheme = caps.get(1).map(|g| g.as_str()).unwrap_or("");
                let lineno = line_of_byte_offset(&cleaned, mat.start());
                let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                matches.push(AcRsMatch {
                    library: hdr_sig.library.clone(),
                    fn_name: format!("{}<{}>", hdr_sig.fn_name, scheme),
                    category: hdr_sig.category.clone(),
                    match_strategy: "type-usage".to_string(),
                    callsite: AcRsCallSite {
                        file: file.to_string(),
                        function: enclosing_function(&fn_decls, mat.start()),
                        line: lineno,
                    },
                    parameters: vec![],
                    raw_line,
                    ac_hint: None,
                    verified_via: hdr_sig.verified_via.clone(),
                });
            }
        }
    }

    // ── attribute-macro auth guards (`#[has_permissions(...)]` and friends) ──
    matches.extend(scan_attribute_guards(file, &cleaned, &cleaned_lines, &lines, &fn_decls, sigs));

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

    // Read every .rs file up front (rather than scanning it once per pass)
    // so the cross-file auth-extractor registry below can be built from a
    // first pass over the whole tree and applied on a second, without
    // re-reading anything from disk.
    let mut files: Vec<(String, String)> = Vec::new();
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
        files.push((entry.path().display().to_string(), content));
    }

    // Pass 1: collect custom auth-extractor types (`impl FromRequestParts`/
    // `FromRequest`) across every file in the tree -- cheap relative to the
    // full scan below (just comment-stripping plus two regex passes per
    // file), so this doesn't scan each file's full pattern set twice. See
    // `AcRsScanOptions::known_auth_extractors`.
    let mut known_extractors: Vec<KnownAuthExtractor> = Vec::new();
    for (path, content) in &files {
        let cleaned = strip_comments(content);
        let lines: Vec<&str> = content.lines().collect();
        for m in detect_local_auth_extractors(path, &cleaned, &lines, sigs) {
            known_extractors.push(KnownAuthExtractor {
                type_name: m.parameters.first().cloned().unwrap_or_default(),
                library: m.library,
                fn_name: m.fn_name,
                verified_via: m.verified_via,
            });
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        known_extractors.retain(|e| seen.insert(e.type_name.clone()));
    }

    // Pass 2: the full scan, now with pass 1's tree-wide registry merged into
    // every file's options -- lets a handler in one file (`current_user:
    // Jwt`) be recognized even though `Jwt`'s own `impl FromRequestParts` is
    // defined in a completely different file.
    let mut full_opts = opts.clone();
    full_opts.known_auth_extractors.extend(known_extractors);

    let mut matches = Vec::new();
    for (path, content) in &files {
        matches.extend(scan_ac_rs_source(path, content, sigs, &full_opts));
    }

    Ok(matches)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ac_finder::load_ac_signatures;

    fn datasets_path() -> &'static Path {
        Box::leak(Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").into_boxed_path())
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
        assert_eq!(hit.verified_via, "general-knowledge");
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
    fn distant_bare_qualified_reference_no_longer_satisfies_the_gate() {
        // Scope-aware gating: a crate referenced only via a bare
        // fully-qualified path (no `use` statement) far from the call site
        // no longer satisfies the crate-reference gate -- unlike a `use`
        // import, which is genuinely file-wide evidence and stays that way
        // (see `has_use_import`/`crate_is_referenced_near`'s doc comments).
        let padding: String = (0..80).map(|i| format!("const PADDING_{i}: i32 = {i};\n")).collect();
        let src = format!(
            r#"
fn other_stuff_using_casbin() {{
    let _ = casbin::CoreApi::enforce_mut;
}}

{padding}

fn unrelated(policy: &LocalPolicy) -> bool {{
    policy.enforce()
}}
"#
        );
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("far.rs", &src, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "casbin-rs" || m.callsite.function != "unrelated"),
            "a bare casbin:: reference 80+ lines away should no longer satisfy the crate-reference gate: {:#?}",
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

    // ── `use ... as alias` resolution ────────────────────────────────────

    #[test]
    fn detects_aliased_free_function_call() {
        const SRC: &str = r#"
use jsonwebtoken::decode as jwt_decode;

fn verify_token(token: &str, key: &DecodingKey, validation: &Validation) -> Result<TokenData<Claims>, Error> {
    jwt_decode::<Claims>(token, key, validation)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("auth.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "jsonwebtoken" && m.match_strategy == "short-name-alias")
            .expect("no alias-resolved jsonwebtoken::decode match");
        assert_eq!(hit.fn_name, "jsonwebtoken::decode");
        assert_eq!(hit.callsite.function, "verify_token");
    }

    #[test]
    fn detects_aliased_free_function_call_via_grouped_use() {
        const SRC: &str = r#"
use jsonwebtoken::{decode as jwt_decode, DecodingKey};

fn verify_token(token: &str, key: &DecodingKey, validation: &Validation) {
    let _ = jwt_decode::<Claims>(token, key, validation);
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("auth.rs", SRC, &sigs, &opts());
        assert!(
            matches
                .iter()
                .any(|m| m.library == "jsonwebtoken" && m.match_strategy == "short-name-alias"),
            "expected an alias-resolved match via the grouped `use` form: {:#?}",
            matches
        );
    }

    #[test]
    fn detects_aliased_type_method_call() {
        const SRC: &str = r#"
use actix_web_httpauth::middleware::HttpAuthentication as Auth;

fn build_auth_middleware() -> Auth<Claims, fn() -> ()> {
    Auth::bearer(validator)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("mw.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "actix-web-httpauth" && m.match_strategy == "type-method-alias")
            .expect("no alias-resolved HttpAuthentication::bearer match");
        assert_eq!(hit.callsite.function, "build_auth_middleware");
    }

    #[test]
    fn aliased_fn_declaration_sharing_the_alias_name_is_not_a_call() {
        const SRC: &str = r#"
use jsonwebtoken::decode as jwt_decode;

fn jwt_decode(token: &str) -> bool {
    true
}

fn verify(token: &str) -> bool {
    jwt_decode(token)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("auth.rs", SRC, &sigs, &opts());
        let hits: Vec<_> = matches.iter().filter(|m| m.match_strategy == "short-name-alias").collect();
        assert_eq!(hits.len(), 1, "expected exactly one real call site, not the declaration: {:#?}", hits);
        assert_eq!(hits[0].callsite.function, "verify");
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

    // ── attribute-macro auth guards ──────────────────────────────────────

    #[test]
    fn detects_attribute_guard_and_attributes_it_to_the_following_function() {
        const SRC: &str = r#"
use actix_web_grants::authorities::AuthDetails;

fn unrelated_earlier_function() {}

#[has_permissions("ROLE_ADMIN")]
async fn admin_only_handler() -> &'static str {
    "ok"
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("guard.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.fn_name == "actix_web_grants::proc_macro::has_permissions")
            .expect("no has_permissions attribute match");
        assert_eq!(hit.match_strategy, "attribute");
        assert_eq!(hit.category, "authorization");
        // Must be attributed to the function it decorates, not the previous
        // one -- the attribute sits above its target, so `enclosing_function`
        // (last fn seen before the offset) would get this wrong.
        assert_eq!(hit.callsite.function, "admin_only_handler");
        assert_eq!(hit.parameters, vec![r#""ROLE_ADMIN""#]);
    }

    #[test]
    fn attribute_guard_suppressed_without_crate_reference() {
        const SRC: &str = r#"
#[has_permissions("ROLE_ADMIN")]
async fn admin_only_handler() -> &'static str {
    "ok"
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("guard.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "actix-web-grants"),
            "unexpected actix-web-grants match without a crate reference: {:#?}",
            matches
        );
    }

    #[test]
    fn attribute_guard_is_not_double_reported_by_the_ordinary_call_loop() {
        // "attribute"-kind signatures are excluded from the ordinary SDK
        // loop (which would otherwise also match `has_permissions(` via the
        // generic "short-name" strategy, mis-attributed via
        // `enclosing_function` instead of `following_function`).
        const SRC: &str = r#"
use actix_web_grants::authorities::AuthDetails;

#[has_permissions("ROLE_ADMIN")]
async fn admin_only_handler() -> &'static str {
    "ok"
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("guard.rs", SRC, &sigs, &opts());
        let hits: Vec<_> = matches
            .iter()
            .filter(|m| m.fn_name == "actix_web_grants::proc_macro::has_permissions")
            .collect();
        assert_eq!(hits.len(), 1, "expected exactly one match, not a duplicate via short-name: {:#?}", hits);
    }

    #[test]
    fn detects_custom_axum_auth_extractor_via_from_request_parts() {
        // Mirrors bionic-gpt's crates/web-server/jwt.rs: a hand-rolled auth
        // guard built on axum's FromRequestParts, with no third-party auth
        // crate involved -- the pattern the pre-existing catalogue couldn't
        // see at all, since it's a trait impl, not a call.
        const SRC: &str = r#"
use axum::{extract::FromRequestParts, http::{request::Parts, StatusCode}};

pub struct Jwt { pub sub: String }

impl<S> FromRequestParts<S> for Jwt
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let access_token = parts.headers.get("X-Forwarded-Access-Token");
        Err((StatusCode::UNAUTHORIZED, "Didn't find an authentication header"))
    }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("jwt.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "axum-extractors" && m.match_strategy == "trait-impl")
            .expect("no custom axum extractor match");
        assert_eq!(hit.category, "authentication");
        assert_eq!(hit.callsite.function, "impl FromRequestParts for Jwt");
        assert!(hit.ac_hint.is_some());
    }

    #[test]
    fn from_request_parts_without_auth_signal_is_not_flagged() {
        // A non-auth axum extractor (e.g. ConnectInfo-style) must not be
        // mistaken for an auth guard just because it implements the same
        // trait.
        const SRC: &str = r#"
use axum::extract::FromRequestParts;

pub struct RequestId(pub String);

impl<S> FromRequestParts<S> for RequestId {
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(RequestId(parts.headers.get("x-request-id").map(|v| v.to_str().unwrap_or("").to_string()).unwrap_or_default()))
    }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("request_id.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "axum-extractors"),
            "unexpected axum-extractors match without an auth signal: {:#?}",
            matches
        );
    }

    #[test]
    fn detects_custom_actix_web_auth_extractor_via_from_request() {
        const SRC: &str = r#"
use actix_web::FromRequest;

pub struct AuthedUser { pub user_id: String }

impl FromRequest for AuthedUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req.headers().get("Authorization").cloned();
        Box::pin(async move { decode_bearer(token).await })
    }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("guard.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "actix-web-extractors" && m.match_strategy == "trait-impl")
            .expect("no actix-web extractor match");
        assert_eq!(hit.category, "authentication");
        assert_eq!(hit.callsite.function, "impl FromRequest for AuthedUser");
    }

    #[test]
    fn from_request_without_auth_signal_is_not_flagged() {
        const SRC: &str = r#"
use actix_web::FromRequest;

pub struct RequestId(pub String);

impl FromRequest for RequestId {
    type Error = ();
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        std::future::ready(Ok(RequestId(req.headers().get("x-request-id").map(|v| v.to_str().unwrap_or("").to_string()).unwrap_or_default())))
    }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("request_id.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "actix-web-extractors"),
            "unexpected actix-web-extractors match without an auth signal: {:#?}",
            matches
        );
    }

    #[test]
    fn from_request_parts_does_not_cross_match_actix_web_extractors() {
        // Word-boundary regression: `impl FromRequestParts<S> for X` must not
        // also fire the actix-web `FromRequest` regex, since "FromRequest" is
        // a strict textual prefix of "FromRequestParts".
        const SRC: &str = r#"
use axum::extract::FromRequestParts;
use actix_web::FromRequest;

pub struct AuthedUser { pub user_id: String }

impl<S> FromRequestParts<S> for AuthedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.headers.get("Authorization").ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(AuthedUser { user_id: decode(token)? })
    }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("guard.rs", SRC, &sigs, &opts());
        let axum_hits: Vec<_> = matches.iter().filter(|m| m.library == "axum-extractors").collect();
        let actix_hits: Vec<_> = matches.iter().filter(|m| m.library == "actix-web-extractors").collect();
        assert_eq!(axum_hits.len(), 1, "expected exactly one axum-extractors match: {:#?}", matches);
        assert!(actix_hits.is_empty(), "FromRequestParts impl was double-counted as actix-web-extractors: {:#?}", matches);
    }

    #[test]
    fn strip_comments_blanks_line_and_block_comments_but_preserves_line_numbers() {
        const SRC: &str = "// a line comment\nfn real() {}\n/* a block\n   comment */\nfn other() {}\n";
        let cleaned = strip_comments(SRC);
        assert_eq!(cleaned.lines().count(), SRC.lines().count());
        assert!(!cleaned.contains("a line comment"));
        assert!(!cleaned.contains("a block"));
        assert!(cleaned.contains("fn real() {}"));
        assert!(cleaned.contains("fn other() {}"));
    }

    #[test]
    fn strip_comments_handles_nested_block_comments() {
        const SRC: &str = "/* outer /* inner */ still outer */fn real() {}";
        let cleaned = strip_comments(SRC);
        assert!(!cleaned.contains("outer"));
        assert!(!cleaned.contains("inner"));
        assert!(cleaned.contains("fn real() {}"));
    }

    #[test]
    fn strip_comments_preserves_string_literals_containing_slashes() {
        // A URL literal contains "//" right after the scheme -- must not be
        // mistaken for a line comment starting mid-string.
        const SRC: &str = r#"let url = "https://example.com/introspect";"#;
        let cleaned = strip_comments(SRC);
        assert_eq!(cleaned, SRC);
    }

    #[test]
    fn call_shaped_text_inside_a_doc_comment_is_not_reported() {
        // Regression test for the exact bug found while writing
        // examples/src/ac_demo.rs's own explanatory comments: a doc comment
        // *describing* `.bearer_auth(...)` must not itself be matched as a
        // real call.
        const SRC: &str = r#"
use reqwest::Client;

/// Deliberately doesn't call `.bearer_auth(token)` here -- see the module
/// docs for why.
async fn whoami(client: &Client) -> String {
    String::new()
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("whoami.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "outbound-credential-header"),
            "call-shaped text inside a doc comment was mistaken for a real call: {:#?}",
            matches
        );
    }

    #[test]
    fn detects_typed_bearer_auth_header_extraction() {
        // Mirrors bionic-gpt's crates/postgres-mcp/src/auth.rs.
        const SRC: &str = r#"
use axum_extra::{extract::TypedHeader, headers::{authorization::Bearer, Authorization}};

async fn from_request_parts(parts: &mut Parts) -> Result<String, ApiError> {
    let TypedHeader(Authorization(bearer)) =
        TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, &()).await?;
    Ok(bearer.token().to_string())
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("auth.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "axum-extractors" && m.match_strategy == "type-usage")
            .expect("no typed bearer header match");
        assert_eq!(hit.category, "authentication");
        assert!(hit.fn_name.ends_with("<Bearer>"));
    }

    #[test]
    fn detects_outbound_authorization_header() {
        // Mirrors traceloop/hub's crates/providers/openai/provider.rs.
        const SRC: &str = r#"
use reqwest::Client;

async fn chat_completion(client: &Client, api_key: &str) -> reqwest::Result<reqwest::Response> {
    client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("provider.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "outbound-credential-header" && m.match_strategy == "http-auth-header")
            .expect("no outbound Authorization header match");
        assert_eq!(hit.category, "authentication");
        assert!(hit.fn_name.contains("Authorization"));
        assert!(hit.ac_hint.is_some());
    }

    #[test]
    fn detects_vendor_api_key_header_variants() {
        // Mirrors anthropic's x-api-key and azure's api-key headers.
        const SRC: &str = r#"
use reqwest::Client;

async fn call_anthropic(client: &Client, key: &str) {
    let _ = client.post("https://api.anthropic.com/v1/messages").header("x-api-key", key).send();
}

async fn call_azure(client: &Client, key: &str) {
    let _ = client.post("https://example.openai.azure.com").header("api-key", key).send();
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("provider.rs", SRC, &sigs, &opts());
        let hits: Vec<_> = matches.iter().filter(|m| m.library == "outbound-credential-header").collect();
        assert_eq!(hits.len(), 2, "expected both x-api-key and api-key to be caught: {:#?}", matches);
    }

    #[test]
    fn detects_bearer_auth_method() {
        // Mirrors traceloop/hub's vertexai/provider.rs service-account path.
        const SRC: &str = r#"
use reqwest::Client;

async fn call_vertex(client: &Client, auth_token: String) {
    let _ = client.post("https://vertex.example.com").bearer_auth(auth_token).send();
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("provider.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.fn_name == "reqwest::RequestBuilder::bearer_auth")
            .expect("no bearer_auth match");
        assert_eq!(hit.category, "authentication");
    }

    #[test]
    fn non_credential_header_is_not_flagged() {
        const SRC: &str = r#"
use reqwest::Client;

async fn fetch(client: &Client) {
    let _ = client.get("https://example.com").header("Content-Type", "application/json").send();
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("fetch.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "outbound-credential-header"),
            "unexpected match on a non-credential header: {:#?}",
            matches
        );
    }

    // ── dynamic (non-literal) outbound header name ──────────────────────

    #[test]
    fn detects_dynamic_outbound_header_name_near_auth_signal() {
        // Mirrors bionic-gpt's tool-runtime/builtin_tools/openapi_tool_adapter.rs:
        // the header name comes from a config field (built elsewhere, hence
        // the file-wide "bearer" signal instead of a nearby-line one) and is
        // applied via a generic passthrough loop.
        const SRC: &str = r#"
use reqwest::Client;

async fn build_auth_header(auth_header_name: &str, token: &str) -> (String, String) {
    // Adding bearer token to the request
    (auth_header_name.to_string(), format!("Bearer {}", token))
}

async fn send_with_headers(client: &Client, headers: Vec<(String, String)>) {
    let mut request = client.get("https://example.com");
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let _ = request.send().await;
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("adapter.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "outbound-credential-header" && m.match_strategy == "http-auth-header-dynamic")
            .expect("no dynamic outbound header match");
        assert_eq!(hit.callsite.function, "send_with_headers");
        assert!(hit.ac_hint.as_deref().unwrap_or("").contains("verify manually"));
    }

    #[test]
    fn dynamic_outbound_header_without_file_wide_signal_is_not_flagged() {
        const SRC: &str = r#"
use reqwest::Client;

async fn send_with_headers(client: &Client, headers: Vec<(String, String)>) {
    let mut request = client.get("https://example.com");
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let _ = request.send().await;
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("proxy.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.match_strategy != "http-auth-header-dynamic"),
            "unexpected dynamic-header match without any auth signal in the file: {:#?}",
            matches
        );
    }

    // ── inbound credential-header check ──────────────────────────────────

    #[test]
    fn detects_inbound_authorization_header_field_style() {
        // Mirrors bionic-gpt's crates/web-server/handlers/api_pipeline.rs.
        const SRC: &str = r#"
use axum::http::header::HeaderMap;

async fn upload(headers: HeaderMap) -> Result<(), String> {
    if let Some(api_key) = headers.get("Authorization") {
        let api_key = api_key.to_str().unwrap().replace("Bearer ", "");
        Ok(())
    } else {
        Err("You need an API key".to_string())
    }
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("api_pipeline.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "inbound-credential-header" && m.match_strategy == "inbound-auth-header")
            .expect("no inbound Authorization header match");
        assert_eq!(hit.category, "authentication");
        assert_eq!(hit.callsite.function, "upload");
        assert!(hit.ac_hint.as_deref().unwrap_or("").contains("inbound"));
    }

    #[test]
    fn detects_inbound_authorization_header_method_style() {
        // actix-web's HttpRequest::headers() returns the map via a method
        // call rather than a field.
        const SRC: &str = r#"
async fn guard(req: &HttpRequest) -> bool {
    req.headers().get("Authorization").is_some()
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("guard.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "inbound-credential-header" && m.match_strategy == "inbound-auth-header")
            .expect("no inbound Authorization header match (method style)");
        assert_eq!(hit.callsite.function, "guard");
    }

    #[test]
    fn inbound_header_get_not_flagged_without_header_receiver() {
        // ".get(" is generic (HashMap/Option/Vec/...); without a "header"-ish
        // receiver or the ".headers()." method chain, this must not fire.
        const SRC: &str = r#"
fn lookup(map: &std::collections::HashMap<String, String>) -> Option<&String> {
    map.get("Authorization")
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("lookup.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "inbound-credential-header"),
            "unexpected match on a generic HashMap::get: {:#?}",
            matches
        );
    }

    #[test]
    fn inbound_header_get_not_flagged_for_non_credential_header() {
        const SRC: &str = r#"
async fn handler(headers: axum::http::HeaderMap) {
    let _ = headers.get("Content-Type");
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("handler.rs", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "inbound-credential-header"),
            "unexpected match on a non-credential header: {:#?}",
            matches
        );
    }

    // ── handler-parameter usage of a known custom auth-extractor type ────

    #[test]
    fn detects_extractor_used_as_handler_parameter_same_file() {
        // The other half of the axum-extractors trait-impl pattern: bionic-gpt
        // handlers never re-implement FromRequestParts, they just take the
        // already-defined `Jwt` type as an ordinary parameter.
        const SRC: &str = r#"
use axum::extract::FromRequestParts;

pub struct Jwt { pub sub: String }

impl<S> FromRequestParts<S> for Jwt
where
    S: Send + Sync,
{
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.headers.get("Authorization");
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}

pub async fn view_document(current_user: Jwt, doc_id: String) -> String {
    format!("{} viewing {}", current_user.sub, doc_id)
}
"#;
        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_source("handlers.rs", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "axum-extractors" && m.match_strategy == "extractor-param-usage")
            .expect("no extractor-param-usage match");
        assert_eq!(hit.category, "authentication");
        assert_eq!(hit.callsite.function, "view_document");
    }

    #[test]
    fn detects_extractor_used_as_handler_parameter_across_files_via_scan_path() {
        // The realistic shape: the `impl FromRequestParts for Jwt` lives in
        // one file (jwt.rs), and dozens of handlers in *other* files take
        // `Jwt` as a parameter without ever importing/defining it themselves
        // -- scan_ac_rs_path's two-pass registry is what makes this visible.
        let dir = std::env::temp_dir().join(format!("afg_ac_rs_src_test_extractor_{}", std::process::id()));
        let src_dir = dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();

        fs::write(
            src_dir.join("jwt.rs"),
            r#"
use axum::extract::FromRequestParts;

pub struct Jwt { pub sub: String }

impl<S> FromRequestParts<S> for Jwt
where
    S: Send + Sync,
{
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.headers.get("Authorization");
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}
"#,
        )
        .unwrap();
        fs::write(
            src_dir.join("documents.rs"),
            r#"
use crate::jwt::Jwt;

pub async fn view_document(current_user: Jwt, doc_id: String) -> String {
    format!("{} viewing {}", current_user.sub, doc_id)
}
"#,
        )
        .unwrap();

        let sigs = load_ac_signatures(datasets_path()).unwrap();
        let matches = scan_ac_rs_path(&dir, &sigs, &opts()).unwrap();

        let hit = matches
            .iter()
            .find(|m| m.library == "axum-extractors" && m.match_strategy == "extractor-param-usage" && m.callsite.file.contains("documents.rs"))
            .unwrap_or_else(|| panic!("no cross-file extractor-param-usage match: {:#?}", matches));
        assert_eq!(hit.callsite.function, "view_document");

        fs::remove_dir_all(&dir).ok();
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
