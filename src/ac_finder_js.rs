//! Companion to `ac_finder` (Rust MIR access-control scanner) and sibling of
//! `llm_api_finder_js`: scans JavaScript/TypeScript *source text* for
//! access-control call sites — auth middleware, guard decorators, RBAC/ABAC
//! permission checks, and policy-enforcement calls — instead of LLM SDK
//! calls. Same text-scanning philosophy as `llm_api_finder_js` (regex
//! against a curated signature catalogue plus an import-statement check used
//! to grade confidence), reused almost verbatim.

use crate::ac_hints::find_ac_hint;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAcSignature {
    pub library: String,
    pub pattern: String,
    pub kind: String,
    pub category: String,
    pub packages: Vec<String>,
    pub require_import: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAcCallSite {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAcMatch {
    pub library: String,
    pub pattern: String,
    pub kind: String,
    pub category: String,
    /// "call+import" | "call-only" | "http+path-hint" | "http-call-only" |
    /// "reference+import" | "reference" | "reference+alias+import" |
    /// "reference+alias"
    pub match_strategy: String,
    pub callsite: JsAcCallSite,
    pub raw_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ac_hint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AcScanOptions {
    /// Report every fetch()/axios()/http(s).request() call site, even when no
    /// known access-control REST path suffix is found nearby. Off by
    /// default: ordinary frontend code calls fetch() constantly for reasons
    /// that have nothing to do with access control, so unconditional
    /// reporting is noise rather than signal.
    pub all_http_calls: bool,
    /// Descend into node_modules. Off by default (vendored dependency source
    /// isn't the target's own code and is usually enormous).
    pub include_node_modules: bool,
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load all JS/TS access-control signatures from
/// `datasets_path/ac_functions_js.json`.
pub fn load_ac_js_signatures(datasets_path: &Path) -> Result<Vec<JsAcSignature>, Box<dyn Error>> {
    let json_path = datasets_path.join("ac_functions_js.json");
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
            let pattern = call.get("pattern").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if pattern.is_empty() {
                continue;
            }
            let kind = call.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let category = call
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified")
                .to_string();
            let require_import = call.get("require_import").and_then(|v| v.as_bool()).unwrap_or(false);
            sigs.push(JsAcSignature {
                library: lib_name.clone(),
                pattern,
                kind,
                category,
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

// "..." | '...' | `...`  (template literals treated as opaque text)
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
const HINT_WINDOW_BEFORE: usize = 6;
const HINT_WINDOW_AFTER: usize = 2;

// ── Bare-reference (middleware-by-reference) detection ─────────────────────────
//
// Express-style routes commonly pass a guard *by reference*, not as a call:
// `router.get('/admin', requireAuth, handler)`. Nothing in that line looks
// like `requireAuth(`, so the call-shape matchers above never see it. This
// section finds Express-ish route-registration/mount calls
// (`app.get(...)`, `router.use(...)`, etc.), parses their argument list with
// a small paren/bracket/string-aware scanner (not a full parser — same
// heuristic philosophy as the rest of this file), and reports any argument
// that is *exactly* a known AC pattern (or a `something.pattern` member
// access), whether or not it's ever invoked.
//
// The receiver name is restricted to common Express conventions (`app`,
// `router`, `route`, `server`, or an identifier ending in one of those —
// `adminRouter`, `apiApp`, ...; see `looks_like_express_receiver`) to keep
// this from firing on unrelated `.get(`/`.use(` calls (`Map.get`, RxJS
// `.use()`, etc.) — a heuristic, not a guarantee.

static RE_ROUTE_TRIGGER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\.(?:get|post|put|patch|delete|all|use|route)\s*\(").unwrap()
});

/// Whether `name` looks like a plausible Express `app`/`Router` receiver.
/// Exact matches (`app`, `router`, `route`, `server`) plus common naming
/// conventions (`adminRouter`, `apiApp`, ...). A heuristic, not a guarantee —
/// see the module doc comment above.
fn looks_like_express_receiver(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "app" | "router" | "route" | "server")
        || lower.ends_with("router")
        || lower.ends_with("app")
}

/// Upper bound on how many characters of a route-registration call's
/// argument list we'll scan looking for the matching close paren. Bounds
/// cost on huge/minified files; a call whose args exceed this is skipped
/// rather than mis-parsed.
const MAX_ROUTE_ARG_SCAN: usize = 4000;

/// Find the byte offset (into `s`, absolute) of the `)` that closes the `(`
/// already consumed just before `start`. Tracks nested `()`/string literals
/// so a comma or paren inside a string or a nested call doesn't confuse
/// depth tracking. Returns `None` if unmatched within `MAX_ROUTE_ARG_SCAN`
/// characters.
fn find_matching_close_paren(s: &str, start: usize) -> Option<usize> {
    let chars: Vec<char> = s[start..].chars().collect();
    let mut depth = 1i32;
    let mut in_string: Option<char> = None;
    let mut i = 0usize;
    while i < chars.len() && i < MAX_ROUTE_ARG_SCAN {
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

/// Split `s` on top-level commas (depth 0 across `()`/`[]`/`{}`, ignoring
/// commas inside string/template literals). Returns byte-offset `(start,
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
    let mut in_string: Option<char> = None;
    let mut seg_start = 0usize;
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

// ── Single-hop alias resolution ─────────────────────────────────────────────
//
// A route often binds a guard to a local name first, then passes the name by
// reference: `const guard = passport.authenticate("jwt"); router.get("/x",
// guard, handler);`. Nothing at the route call site looks like a cataloged
// pattern -- `guard` is just an identifier -- so the bare-reference detection
// below (which only recognizes the pattern's own name) misses it. This pass
// closes that specific, common case: it looks for `const/let/var IDENT =
// <call-shape>` declarations anywhere in the file and records IDENT -> the
// signature(s) its RHS matched, so the bare-reference scan can resolve
// through one level of aliasing.
//
// This is intentionally a single hop, file-scoped lookup, not real data-flow
// analysis: `const a = guard; const b = a;` won't resolve, reassignment
// isn't tracked, and an alias declared in one file can't be resolved from an
// import of it in another file. See "Known blind spots" in AC_FINDER_JS.md.

static RE_ALIAS_DECL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*").unwrap()
});

/// Upper bound on how many characters of an alias assignment's RHS to scan
/// looking for the statement-ending top-level `;`. Same rationale as
/// `MAX_ROUTE_ARG_SCAN`: bounds cost and turns a missing semicolon (or a huge
/// minified file) into a truncated-but-safe scan rather than a hang.
const MAX_ALIAS_RHS_SCAN: usize = 4000;

/// Find the byte offset of the first top-level (depth-0 across
/// `()`/`[]`/`{}`, string-aware) `;` at or after `start` -- the end of the
/// statement that began at `start`. Falls back to the scan bound if no
/// semicolon is found there (e.g. the statement runs past
/// `MAX_ALIAS_RHS_SCAN`), which just makes the RHS text used for matching a
/// truncated best-effort rather than a hard failure.
fn find_statement_end(s: &str, start: usize) -> usize {
    let chars: Vec<char> = s[start..].chars().collect();
    let mut depth = 0i32;
    let mut in_string: Option<char> = None;
    let mut i = 0usize;
    while i < chars.len() && i < MAX_ALIAS_RHS_SCAN {
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
            '(' | '[' | '{' => {
                depth += 1;
                i += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                i += 1;
            }
            ';' if depth <= 0 => {
                let byte_off: usize = chars[..i].iter().map(|c| c.len_utf8()).sum();
                return start + byte_off;
            }
            _ => i += 1,
        }
    }
    let byte_off: usize = chars[..i].iter().map(|c| c.len_utf8()).sum();
    start + byte_off
}

/// Scan `content` for `const/let/var IDENT = <expr>;` declarations whose RHS
/// matches one of `matchers`' call-shape patterns, respecting the same
/// import-confirmation gate ordinary call matches use (a `require_import`
/// signature that isn't confirmed by an import never gets recorded here
/// either). Returns IDENT -> one `(signature, was-import-confirmed)` entry
/// per distinct signature it matched -- more than one only in the same rare
/// cross-library ambiguity case the call-shape matcher already tolerates.
fn build_alias_map<'a>(
    content: &str,
    matchers: &[CallMatcher<'a>],
    imports: &HashSet<String>,
) -> HashMap<String, Vec<(&'a JsAcSignature, bool)>> {
    let mut map: HashMap<String, Vec<(&'a JsAcSignature, bool)>> = HashMap::new();
    for caps in RE_ALIAS_DECL.captures_iter(content) {
        let ident = caps[1].to_string();
        let rhs_start = caps.get(0).unwrap().end();
        let rhs_end = find_statement_end(content, rhs_start);
        let rhs = &content[rhs_start..rhs_end];

        for m in matchers {
            if !m.pattern.is_match(rhs) {
                continue;
            }
            let confirmed = import_satisfies(imports, &m.sig.packages);
            if m.sig.require_import && !confirmed {
                continue;
            }
            map.entry(ident.clone()).or_default().push((m.sig, confirmed));
        }
    }
    map
}

/// Extract candidate bare-reference arguments from a route call's argument
/// text: each top-level comma-separated argument, trimmed, with one level of
/// `[...]` array-literal unwrapping (covers the common `[auth, isAdmin]`
/// middleware-array pattern). Returns `(trimmed_text, absolute_byte_offset)`
/// pairs, offset relative to the start of `args_text`.
fn collect_reference_candidates(args_text: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (start, end) in split_top_level_commas(args_text) {
        let raw = &args_text[start..end];
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let ws_prefix = raw.len() - raw.trim_start().len();
        let abs_start = start + ws_prefix;

        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            let inner = &trimmed[1..trimmed.len() - 1];
            let inner_base = abs_start + 1;
            for (istart, iend) in split_top_level_commas(inner) {
                let iraw = &inner[istart..iend];
                let itrimmed = iraw.trim();
                if itrimmed.is_empty() {
                    continue;
                }
                let iws = iraw.len() - iraw.trim_start().len();
                out.push((itrimmed.to_string(), inner_base + istart + iws));
            }
        } else {
            out.push((trimmed.to_string(), abs_start));
        }
    }
    out
}

fn line_of_byte_offset(content: &str, offset: usize) -> usize {
    content.as_bytes()[..offset].iter().filter(|&&b| b == b'\n').count() + 1
}

/// Whether the call-shape match starting at byte offset `start` within
/// `line` is actually the name in a `function requireRole(...)`-style
/// declaration rather than a call — e.g. a codebase's own in-house
/// `requireRole()` guard shares its name with a `generic-authz-checks`
/// catalogue pattern, and nothing but what precedes the `(` distinguishes a
/// declaration from a call. Mirrors `is_fn_declaration` in
/// `ac_finder_rs_src.rs`, adapted to JS's `function`/`function*` keyword
/// instead of Rust's `fn`. Class/object method-shorthand declarations
/// (`requireRole(role) { ... }`) are textually indistinguishable from a call
/// without full parsing and remain a known blind spot — this only covers
/// the unambiguous `function`-keyword form.
fn is_fn_declaration(line: &str, start: usize) -> bool {
    let mut trimmed = line[..start].trim_end();
    if let Some(stripped) = trimmed.strip_suffix('*') {
        trimmed = stripped.trim_end();
    }
    let Some(prefix) = trimmed.strip_suffix("function") else {
        return false;
    };
    match prefix.chars().next_back() {
        Some(c) => !c.is_alphanumeric() && c != '_' && c != '$',
        None => true,
    }
}

// ── Comment stripping ────────────────────────────────────────────────────────

/// Replace `//` line comments and `/* */` block comments with spaces,
/// leaving every newline and every other character -- including
/// string/template-literal contents, since `raw-http-authz`'s `ac_hint`
/// scanning needs those intact -- untouched. Mirrors
/// `ac_finder_rs_src::strip_comments`: an example call pattern written out
/// in an explanatory comment must not be mistaken for a real call, and a
/// stray unbalanced `(`/`{` in a comment must not desync the paren/brace
/// depth-scanners elsewhere in this file. Line numbers computed against the
/// result line up exactly with the original, since replacing characters
/// with spaces never adds or removes a `\n`.
///
/// Unlike Rust, JS/TS block comments do **not** nest -- `/* outer /* inner
/// */ still outer */` ends at the first `*/`, and " still outer */" is live
/// (if malformed) code -- so this doesn't track comment depth the way the
/// Rust version does.
///
/// Doesn't special-case regex literals (`/pattern/flags`) -- same class of
/// trade-off this file already accepts for paren/string scanning elsewhere
/// (`find_matching_close_paren` etc. don't understand them either): a regex
/// containing a literal, unescaped `/*`-looking sequence (rare -- regex
/// literals almost always escape internal `/`) could in principle be
/// misread as starting a block comment.
fn strip_comments(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut i = 0usize;
    let mut in_string: Option<char> = None;

    while i < chars.len() {
        let c = chars[i];

        if let Some(q) = in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                in_string = None;
            }
            i += 1;
            continue;
        }

        if c == '\'' || c == '"' || c == '`' {
            in_string = Some(c);
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
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < chars.len() {
                if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    break;
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

// ── Scanner ───────────────────────────────────────────────────────────────────

struct CallMatcher<'a> {
    sig: &'a JsAcSignature,
    pattern: Regex,
}

fn make_call_matchers(sigs: &[JsAcSignature]) -> Vec<CallMatcher<'_>> {
    sigs.iter()
        .filter_map(|sig| {
            // Leading \b so a single-word catalogue pattern only matches a
            // real standalone identifier -- without it, generic names like
            // casl's "can" or jsonwebtoken's "verify" match as *substrings*
            // of unrelated calls (`scan(`, `reauth(`, `jwtverify(`), which is
            // a real false-positive source since these patterns already rely
            // on `require_import` (or the caller's own judgment for
            // generic-authz-checks) rather than specificity to stay useful.
            // Mirrors the boundary check `make_source_matchers` already does
            // for the Rust source scanner's "short-name"/"type-method"
            // strategies.
            let pat = format!(r"\b{}\s*\(", regex::escape(&sig.pattern));
            Regex::new(&pat).ok().map(|pattern| CallMatcher { sig, pattern })
        })
        .collect()
}

fn collect_imports(content: &str) -> HashSet<String> {
    RE_IMPORT.captures_iter(content).map(|c| c[1].to_string()).collect()
}

fn import_satisfies(imports: &HashSet<String>, packages: &[String]) -> bool {
    packages.iter().any(|pkg| {
        imports.contains(pkg) || imports.iter().any(|imp| imp.starts_with(&format!("{pkg}/")))
    })
}

/// Scan one file's already-read source text. `file` is the path/label used in
/// reported callsites; it need not exist on disk (useful for tests).
pub fn scan_ac_js_source(
    file: &str,
    content: &str,
    sigs: &[JsAcSignature],
    opts: &AcScanOptions,
) -> Vec<JsAcMatch> {
    // All matching/gating below runs against `cleaned` (comments blanked to
    // spaces), not `content` -- see `strip_comments`. `content`/`lines` stay
    // around purely so `raw_line` shows the real, unmodified source text.
    let cleaned = strip_comments(content);
    let imports = collect_imports(&cleaned);
    let matchers = make_call_matchers(sigs);
    let alias_map = build_alias_map(&cleaned, &matchers, &imports);

    let lines: Vec<&str> = content.lines().collect();
    let cleaned_lines: Vec<&str> = cleaned.lines().collect();

    let literals: Vec<Vec<String>> = cleaned_lines
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

    for (idx, cline) in cleaned_lines.iter().enumerate() {
        let lineno = idx + 1;
        let raw_line = lines.get(idx).map(|l| l.trim().to_string()).unwrap_or_default();

        // ── AC call-shape matches ──
        // Collect spans first: some patterns are textual substrings of a more
        // specific pattern in the same library (e.g. "verify" inside
        // "jwt.verify") — reporting both for one call site is a duplicate,
        // not a finding. Cross-library overlaps are kept — genuine ambiguity.
        let candidates: Vec<(&CallMatcher, usize, usize)> = matchers
            .iter()
            .filter_map(|m| m.pattern.find(cline).map(|mat| (m, mat.start(), mat.end())))
            .collect();

        for (i, (m, start, end)) in candidates.iter().enumerate() {
            let shadowed = candidates.iter().enumerate().any(|(j, (other, ostart, oend))| {
                i != j
                    && other.sig.library == m.sig.library
                    && *ostart <= *start
                    && *end <= *oend
                    && (*ostart, *oend) != (*start, *end)
            });
            if shadowed {
                continue;
            }
            if is_fn_declaration(cline, *start) {
                continue; // e.g. `function requireRole(...)` shadowing a call to the same-named pattern
            }
            let confirmed = import_satisfies(&imports, &m.sig.packages);
            if m.sig.require_import && !confirmed {
                continue;
            }
            matches.push(JsAcMatch {
                library: m.sig.library.clone(),
                pattern: m.sig.pattern.clone(),
                kind: m.sig.kind.clone(),
                category: m.sig.category.clone(),
                match_strategy: if confirmed { "call+import" } else { "call-only" }.to_string(),
                callsite: JsAcCallSite { file: file.to_string(), line: lineno },
                raw_line: raw_line.clone(),
                ac_hint: None,
            });
        }

        // ── raw HTTP calls to an access-control service ──
        if RE_HTTP_TRIGGER.is_match(cline) {
            let start = idx.saturating_sub(HINT_WINDOW_BEFORE);
            let end = (idx + HINT_WINDOW_AFTER + 1).min(literals.len());
            let nearby: Vec<&String> = literals[start..end].iter().flatten().collect();
            let hint = find_ac_hint(&nearby);

            if hint.is_some() || opts.all_http_calls {
                matches.push(JsAcMatch {
                    library: "raw-http-authz".to_string(),
                    pattern: RE_HTTP_TRIGGER
                        .find(cline)
                        .map(|m| m.as_str().trim_end_matches('(').trim().to_string())
                        .unwrap_or_default(),
                    kind: "raw HTTP call to an access-control service".to_string(),
                    category: "raw-http".to_string(),
                    match_strategy: if hint.is_some() { "http+path-hint" } else { "http-call-only" }
                        .to_string(),
                    callsite: JsAcCallSite { file: file.to_string(), line: lineno },
                    raw_line,
                    ac_hint: hint,
                });
            }
        }
    }

    // ── Bare-reference (middleware-by-reference) matches ──
    // Operates over the whole file, not per-line, since a route call's
    // argument list can span multiple lines.
    for trigger in RE_ROUTE_TRIGGER.captures_iter(&cleaned) {
        if !looks_like_express_receiver(&trigger[1]) {
            continue;
        }
        let open_paren = trigger.get(0).unwrap().end();
        let Some(close_paren) = find_matching_close_paren(&cleaned, open_paren) else {
            continue;
        };
        let args_text = &cleaned[open_paren..close_paren];

        for (arg, rel_offset) in collect_reference_candidates(args_text) {
            let mut matched_directly = false;
            for sig in sigs {
                let is_reference = arg == sig.pattern || arg.ends_with(&format!(".{}", sig.pattern));
                if !is_reference {
                    continue;
                }
                matched_directly = true;
                let confirmed = import_satisfies(&imports, &sig.packages);
                if sig.require_import && !confirmed {
                    continue;
                }
                let abs_offset = open_paren + rel_offset;
                let lineno = line_of_byte_offset(&cleaned, abs_offset);
                let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                matches.push(JsAcMatch {
                    library: sig.library.clone(),
                    pattern: sig.pattern.clone(),
                    kind: format!("{} (middleware passed by reference, not invoked)", sig.kind),
                    category: sig.category.clone(),
                    match_strategy: if confirmed { "reference+import" } else { "reference" }.to_string(),
                    callsite: JsAcCallSite { file: file.to_string(), line: lineno },
                    raw_line,
                    ac_hint: None,
                });
            }

            // `arg` didn't textually match a cataloged pattern name itself --
            // check whether it's a local alias for one (single-hop only; see
            // "Single-hop alias resolution" above).
            if !matched_directly {
                if let Some(hits) = alias_map.get(&arg) {
                    let abs_offset = open_paren + rel_offset;
                    let lineno = line_of_byte_offset(&cleaned, abs_offset);
                    let raw_line = lines.get(lineno - 1).map(|l| l.trim().to_string()).unwrap_or_default();
                    for (sig, confirmed) in hits {
                        matches.push(JsAcMatch {
                            library: sig.library.clone(),
                            pattern: sig.pattern.clone(),
                            kind: format!(
                                "{} (middleware passed by reference via local alias `{arg}`, not invoked)",
                                sig.kind
                            ),
                            category: sig.category.clone(),
                            match_strategy: if *confirmed { "reference+alias+import" } else { "reference+alias" }
                                .to_string(),
                            callsite: JsAcCallSite { file: file.to_string(), line: lineno },
                            raw_line: raw_line.clone(),
                            ac_hint: None,
                        });
                    }
                }
            }
        }
    }

    matches
}

const SCAN_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];

/// Walk `root` (a file or a directory) and scan every JS/TS source file
/// found under it.
pub fn scan_ac_path(
    root: &Path,
    sigs: &[JsAcSignature],
    opts: &AcScanOptions,
) -> Result<Vec<JsAcMatch>, Box<dyn Error>> {
    let mut matches = Vec::new();

    if root.is_file() {
        let content = fs::read_to_string(root)?;
        return Ok(scan_ac_js_source(&root.display().to_string(), &content, sigs, opts));
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
        let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("");
        if !SCAN_EXTENSIONS.contains(&ext) {
            continue;
        }
        let content = match fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue, // skip unreadable/non-UTF8 files rather than aborting the whole scan
        };
        matches.extend(scan_ac_js_source(&entry.path().display().to_string(), &content, sigs, opts));
    }

    Ok(matches)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn datasets_path() -> &'static Path {
        Box::leak(Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").into_boxed_path())
    }

    fn opts() -> AcScanOptions {
        AcScanOptions::default()
    }

    #[test]
    fn loads_all_ac_js_libraries() {
        let sigs = load_ac_js_signatures(datasets_path()).expect("load_ac_js_signatures failed");
        assert!(!sigs.is_empty());
        let libs: Vec<_> = sigs.iter().map(|s| s.library.as_str()).collect();
        for expected in &["passport", "jsonwebtoken", "nestjs-authz", "casl", "casbin-node"] {
            assert!(libs.contains(expected), "library '{expected}' missing");
        }
    }

    #[test]
    fn detects_passport_authenticate() {
        const SRC: &str = r#"
import passport from "passport";
router.get("/admin", passport.authenticate("jwt", { session: false }), handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        let hit = matches.iter().find(|m| m.library == "passport").expect("no passport match");
        assert_eq!(hit.match_strategy, "call+import");
        assert_eq!(hit.category, "authentication");
    }

    #[test]
    fn detects_nestjs_use_guards_decorator() {
        const SRC: &str = r#"
import { UseGuards } from "@nestjs/common";

@UseGuards(JwtAuthGuard, RolesGuard)
export class AdminController {}
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("admin.controller.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "nestjs-authz" && m.pattern == "UseGuards")
            .expect("no UseGuards match");
        assert_eq!(hit.category, "authorization");
    }

    #[test]
    fn generic_pattern_requires_import_to_report() {
        // casl's "can" is too generic to trust without a confirming import.
        const SRC: &str = r#"function scanIt(x) { return can(x); }"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("misc.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "casl"),
            "generic pattern should not fire without import: {:#?}",
            matches
        );
    }

    #[test]
    fn generic_authz_checks_report_without_import() {
        // In-house helpers have no package to import-check against, so they
        // must still fire (as call-only) — otherwise they'd never be found.
        const SRC: &str = r#"
function handler(req, res, next) {
  if (!requireRole(req.user, "admin")) return res.sendStatus(403);
  next();
}
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("mw.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "generic-authz-checks" && m.pattern == "requireRole")
            .expect("expected requireRole match");
        assert_eq!(hit.match_strategy, "call-only");
        assert_eq!(hit.category, "authorization");
    }

    #[test]
    fn raw_fetch_with_known_ac_path_gets_hint() {
        const SRC: &str = r#"
const url = `${authBase}/oauth/token`;
const res = await fetch(url, { method: "POST", body: form });
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("client.js", SRC, &sigs, &opts());
        let hit = matches.iter().find(|m| m.library == "raw-http-authz").expect("no raw-http-authz match");
        assert_eq!(hit.match_strategy, "http+path-hint");
        assert!(hit.ac_hint.as_deref().unwrap().contains("OAuth2"));
    }

    #[test]
    fn raw_fetch_without_known_ac_path_is_suppressed_by_default() {
        const SRC: &str = r#"
const res = await fetch("/api/settings", { method: "GET" });
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("settings.js", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "raw-http-authz"),
            "unhinted fetch() should be suppressed by default: {:#?}",
            matches
        );
    }

    #[test]
    fn fn_declaration_sharing_a_pattern_name_is_not_a_call() {
        const SRC: &str = r#"
function requireRole(role) {
  return function (req, res, next) {
    next();
  };
}
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("guards.ts", SRC, &sigs, &opts());
        assert!(
            matches.is_empty(),
            "a bare `function requireRole(...)` declaration should not be reported as a call: {:#?}",
            matches
        );
    }

    #[test]
    fn fn_declaration_variants_are_not_calls() {
        const SRC: &str = r#"
export async function isAdmin(user) {}
export default function* hasPermission(user) {}
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("guards2.ts", SRC, &sigs, &opts());
        assert!(
            matches.is_empty(),
            "async/generator/export function declarations should not be reported as calls: {:#?}",
            matches
        );
    }

    #[test]
    fn calling_a_pattern_named_after_a_declared_function_is_still_reported() {
        // The declaration itself must be filtered, but an actual call to it
        // elsewhere (or to same-named code in another file) must still fire.
        const SRC: &str = r#"
function requireRole(role) {
  return function (req, res, next) { next(); };
}
router.get("/x", requireRole("admin"), handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("guards3.ts", SRC, &sigs, &opts());
        assert!(
            matches
                .iter()
                .any(|m| m.library == "generic-authz-checks" && m.pattern == "requireRole"),
            "expected the real call site to still be reported: {:#?}",
            matches
        );
    }

    #[test]
    fn generic_pattern_does_not_match_as_a_substring() {
        // Regression test: single-word catalogue patterns like "can"/"auth"/
        // "verify" must only match a standalone identifier, not any
        // identifier ending in those letters -- `scan(`, `reauth(`,
        // `jwtverify(` are unrelated calls that happen to contain the
        // pattern text.
        const SRC: &str = r#"
import { can } from "@casl/ability";
import jwt from "jsonwebtoken";
function scan(list) { return list; }
function reauth(session) { return session; }
function jwtverify(token) { return token; }
scan([1, 2, 3]);
reauth(session);
jwtverify(token);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("misc.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.pattern != "can"),
            "'can' should not match inside 'scan(': {:#?}",
            matches
        );
        assert!(
            matches.iter().all(|m| m.pattern != "auth"),
            "'auth' should not match inside 'reauth(': {:#?}",
            matches
        );
        assert!(
            matches.iter().all(|m| m.pattern != "verify"),
            "'verify' should not match inside 'jwtverify(': {:#?}",
            matches
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
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("Button.tsx", SRC, &sigs, &opts());
        assert!(matches.is_empty(), "unexpected matches: {:#?}", matches);
    }

    // ── comment stripping ────────────────────────────────────────────────

    #[test]
    fn strip_comments_blanks_line_and_block_comments_but_preserves_line_numbers() {
        const SRC: &str = "// a line comment\nfunction real() {}\n/* a block\n   comment */\nfunction other() {}\n";
        let cleaned = strip_comments(SRC);
        assert_eq!(cleaned.lines().count(), SRC.lines().count());
        assert!(!cleaned.contains("a line comment"));
        assert!(!cleaned.contains("a block"));
        assert!(cleaned.contains("function real() {}"));
        assert!(cleaned.contains("function other() {}"));
    }

    #[test]
    fn strip_comments_does_not_nest_block_comments() {
        // Unlike Rust, JS/TS block comments end at the first `*/` regardless
        // of any `/*` seen since -- so the comment here is only "/* outer /*
        // inner */", and the trailing " still outer */" is left alone (it
        // would be live, if malformed, code in real JS).
        const SRC: &str = "/* outer /* inner */ still outer */";
        let cleaned = strip_comments(SRC);
        assert!(!cleaned.contains("inner"));
        assert!(cleaned.contains("still outer */"));
        // The comment portion's own "outer" is blanked -- only the trailing,
        // live-code "outer" survives.
        assert_eq!(cleaned.matches("outer").count(), 1);
    }

    #[test]
    fn strip_comments_preserves_string_and_template_literals_containing_slashes() {
        const SRC: &str = r#"const url = "https://example.com/introspect";"#;
        assert_eq!(strip_comments(SRC), SRC);
        const TEMPLATE: &str = "const url = `https://example.com/${path}`;";
        assert_eq!(strip_comments(TEMPLATE), TEMPLATE);
    }

    #[test]
    fn call_shaped_text_inside_a_comment_is_not_reported() {
        // Regression test mirroring the exact bug found in the Rust source
        // scanner: an explanatory comment describing a call pattern must not
        // itself be matched as a real call.
        const SRC: &str = r#"
import passport from "passport";
// don't call passport.authenticate("jwt") here -- see the module docs
function noop() {}
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("noop.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "passport"),
            "call-shaped text inside a comment was mistaken for a real call: {:#?}",
            matches
        );
    }

    #[test]
    fn commented_out_import_does_not_satisfy_require_import_gate() {
        // A commented-out import must not count as evidence the package is
        // actually available -- jsonwebtoken's bare "verify" pattern
        // requires a confirming import.
        const SRC: &str = r#"
// import jwt from "jsonwebtoken";
const decoded = verify(token, secret);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("auth.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "jsonwebtoken"),
            "commented-out import should not satisfy the require_import gate: {:#?}",
            matches
        );
    }

    #[test]
    fn jsonwebtoken_verify_detected_with_and_without_alias() {
        const SRC: &str = r#"
import jwt from "jsonwebtoken";
const decoded = jwt.verify(token, secret);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("auth.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "jsonwebtoken" && m.pattern == "jwt.verify")
            .expect("no jwt.verify match");
        assert_eq!(hit.category, "authentication");
    }

    // ── bare-reference (middleware-by-reference) detection ──────────────────

    #[test]
    fn detects_bare_reference_middleware_on_express_route() {
        const SRC: &str = r#"
router.get("/admin", requireAuth, (req, res) => {
  res.send("ok");
});
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "generic-authz-checks" && m.pattern == "requireAuth")
            .expect("expected a bare-reference requireAuth match");
        assert_eq!(hit.match_strategy, "reference");
        assert_eq!(hit.callsite.line, 2);
    }

    #[test]
    fn detects_bare_reference_inside_middleware_array() {
        const SRC: &str = r#"
app.get("/admin", [isAuthenticated, requireRole("admin")], handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        // isAuthenticated is passed bare inside the array.
        assert!(
            matches.iter().any(|m| m.library == "generic-authz-checks"
                && m.pattern == "isAuthenticated"
                && m.match_strategy == "reference"),
            "expected bare isAuthenticated reference: {:#?}",
            matches
        );
        // requireRole("admin") is a call, already caught by the call-shape
        // matcher (not the reference matcher) — both should fire once.
        assert!(
            matches
                .iter()
                .any(|m| m.pattern == "requireRole" && m.match_strategy == "call-only"),
            "expected requireRole call-shape match: {:#?}",
            matches
        );
        assert!(
            matches.iter().all(|m| !(m.pattern == "requireRole" && m.match_strategy == "reference")),
            "requireRole was called, not referenced — should not double-report as a reference: {:#?}",
            matches
        );
    }

    #[test]
    fn bare_reference_respects_require_import_gate() {
        const SRC_NO_IMPORT: &str = r#"router.use(jwt);"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("mw.ts", SRC_NO_IMPORT, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "express-jwt"),
            "express-jwt's generic 'jwt' pattern requires a confirming import: {:#?}",
            matches
        );

        const SRC_WITH_IMPORT: &str = r#"
import jwt from "express-jwt";
router.use(jwt);
"#;
        let matches = scan_ac_js_source("mw.ts", SRC_WITH_IMPORT, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "express-jwt" && m.pattern == "jwt")
            .expect("expected express-jwt reference match once import confirms it");
        assert_eq!(hit.match_strategy, "reference+import");
    }

    #[test]
    fn non_express_receiver_does_not_trigger_reference_scan() {
        // `myMap` doesn't end in app/App/router/Router and isn't route/server,
        // so `.get(` here should be left alone (Map.get-style false positive
        // avoidance).
        const SRC: &str = r#"const handler = myMap.get(requireAuth, fallback);"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("misc.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.match_strategy != "reference"),
            "non-Express .get( receiver should not trigger reference scan: {:#?}",
            matches
        );
    }

    #[test]
    fn bare_reference_on_admin_router_variable() {
        // Receiver need not be literally named "router" — anything ending in
        // "Router"/"router"/"app"/"App" should trigger.
        const SRC: &str = r#"adminRouter.post("/ban", isAdmin, banHandler);"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("admin.ts", SRC, &sigs, &opts());
        assert!(
            matches
                .iter()
                .any(|m| m.library == "generic-authz-checks" && m.pattern == "isAdmin" && m.match_strategy == "reference"),
            "expected isAdmin reference on adminRouter.post: {:#?}",
            matches
        );
    }

    // ── single-hop alias resolution ──────────────────────────────────────

    #[test]
    fn resolves_bare_reference_through_local_alias() {
        const SRC: &str = r#"
import passport from "passport";
const guard = passport.authenticate("jwt", { session: false });
router.get("/admin", guard, handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        let hit = matches
            .iter()
            .find(|m| m.library == "passport" && m.pattern == "passport.authenticate" && m.match_strategy.starts_with("reference+alias"))
            .expect("expected an alias-resolved passport reference match");
        assert_eq!(hit.match_strategy, "reference+alias+import");
        assert_eq!(hit.callsite.line, 4);
        // The direct call-shape match on the assignment line still fires too
        // -- that's a real call site, independent of the alias reference.
        assert!(
            matches
                .iter()
                .any(|m| m.library == "passport" && m.match_strategy == "call+import" && m.callsite.line == 3),
            "expected the assignment itself to still be reported as a call: {:#?}",
            matches
        );
    }

    #[test]
    fn alias_resolution_respects_require_import_gate() {
        // jsonwebtoken's bare "verify" pattern requires a confirming import;
        // aliasing it shouldn't bypass that gate.
        const SRC: &str = r#"
const check = verify(token, secret);
router.use(check);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("mw.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| m.library != "jsonwebtoken"),
            "unconfirmed 'verify' alias should not be reported: {:#?}",
            matches
        );
    }

    #[test]
    fn alias_resolution_handles_multiline_rhs() {
        const SRC: &str = r#"
import passport from "passport";
const guard = passport.authenticate(
  "jwt",
  { session: false }
);
router.get("/admin", guard, handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        assert!(
            matches
                .iter()
                .any(|m| m.library == "passport" && m.match_strategy == "reference+alias+import"),
            "expected alias resolution to see across a multi-line RHS: {:#?}",
            matches
        );
    }

    #[test]
    fn identifier_matching_a_pattern_name_is_not_double_reported_via_alias() {
        // `requireAuth` textually matches the generic-authz-checks pattern
        // directly -- the alias path must not also fire for it.
        const SRC: &str = r#"
router.get("/admin", requireAuth, handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        let hits: Vec<_> = matches.iter().filter(|m| m.pattern == "requireAuth").collect();
        assert_eq!(hits.len(), 1, "expected exactly one requireAuth match: {:#?}", hits);
        assert_eq!(hits[0].match_strategy, "reference");
    }

    #[test]
    fn multi_hop_alias_is_not_resolved() {
        // Known limitation: this is a single-hop lookup, so a second level of
        // aliasing is intentionally left unresolved.
        const SRC: &str = r#"
import passport from "passport";
const inner = passport.authenticate("jwt");
const guard = inner;
router.get("/admin", guard, handler);
"#;
        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_js_source("routes.ts", SRC, &sigs, &opts());
        assert!(
            matches.iter().all(|m| !(m.match_strategy.starts_with("reference+alias") && m.callsite.line == 5)),
            "second-hop alias should not resolve: {:#?}",
            matches
        );
    }

    #[test]
    fn scan_path_walks_directory_and_skips_node_modules() {
        let dir = std::env::temp_dir().join(format!("afg_ac_js_test_{}", std::process::id()));
        let src_dir = dir.join("src");
        let nm_dir = dir.join("node_modules").join("passport");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&nm_dir).unwrap();

        fs::write(
            src_dir.join("auth.ts"),
            r#"import passport from "passport";
router.get("/admin", passport.authenticate("jwt"), handler);"#,
        )
        .unwrap();
        fs::write(
            nm_dir.join("index.js"),
            r#"module.exports.authenticate = function() { return real.passport.authenticate("jwt"); };"#,
        )
        .unwrap();

        let sigs = load_ac_js_signatures(datasets_path()).unwrap();
        let matches = scan_ac_path(&dir, &sigs, &opts()).unwrap();

        assert!(
            matches.iter().any(|m| m.callsite.file.contains("auth.ts")),
            "expected a match from src/auth.ts: {:#?}",
            matches
        );
        assert!(
            matches.iter().all(|m| !m.callsite.file.contains("node_modules")),
            "node_modules should be skipped by default: {:#?}",
            matches
        );

        fs::remove_dir_all(&dir).ok();
    }
}
