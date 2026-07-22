//! Companion to `ac_finder` (RUPTA MIR) and `ac_finder_rs_src` (Rust source):
//! scans a real LLVM IR module -- textual `.ll` or bitcode `.bc`, as emitted
//! by `rustc --emit=llvm-ir` / `--emit=llvm-bc`, or by clang for a C/C++
//! target -- for calls into known access-control crates/functions. Reuses
//! the same `ac_functions.json` catalogue as `ac_finder`, keyed on demangled
//! Rust item paths (e.g. `jsonwebtoken::decode`).
//!
//! Unlike `ac_finder`'s regex-over-text-dump approach, this module parses
//! the IR into the [`llvm-ir`](https://github.com/cdisselkoen/llvm-ir)
//! crate's typed structures and walks `call` instructions directly, so
//! there's no risk of matching inside a string literal or comment. Callee
//! symbols are LLVM linkage names (mangled); each one is demangled via
//! `rustc-demangle` before being matched against the catalogue, which is a
//! no-op passthrough for names that aren't Rust-mangled (see
//! `rustc_demangle::demangle`'s documented fallback behavior).
//!
//! Gated behind the `llvm-ir-scan` Cargo feature -- see
//! `src/AC_FINDER.md#scanning-real-llvm-ir` for why, and for the LLVM
//! version this is pinned to.

use crate::ac_finder::AcSignature;
use llvm_ir::{Constant, HasDebugLoc, Instruction, Module, Name, Operand};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

// Same catalogue, same loader -- `ac_functions.json` entries are already
// keyed on fully-qualified Rust paths, which is exactly what a demangled
// LLVM symbol looks like.
pub use crate::ac_finder::load_ac_signatures as load_ac_llvm_signatures;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcLlvmCallSite {
    /// The calling function, demangled (e.g. `my_app::verify_token`, not
    /// `_ZN6my_app12verify_token17h...E`).
    pub function: String,
    pub block: String,
    /// Index of the `call` instruction within its basic block's instruction
    /// list (0-based). LLVM IR text doesn't carry per-instruction line
    /// numbers unless the module was compiled with debug info, so this is
    /// the stable fallback locator; `line`/`file` are filled in whenever a
    /// `!dbg` attachment is present.
    pub instruction_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcLlvmMatch {
    pub library: String,
    pub fn_name: String,
    pub category: String,
    pub match_strategy: String,
    pub callsite: AcLlvmCallSite,
    /// The callee's mangled linkage name exactly as it appears in the IR.
    pub mangled_name: String,
    /// The callee name after `rustc_demangle`, generic parameters stripped.
    /// What was actually matched against the catalogue.
    pub demangled_name: String,
    /// Best-effort access-control service guess for `raw-http-authz`
    /// matches. Unlike `ac_finder`/`ac_finder_rs_src`, this is always `None`
    /// here: reconstructing nearby string literals from LLVM IR means
    /// resolving `getelementptr` chains into constant globals, which this
    /// scanner doesn't attempt yet. See "Known blind spots" in
    /// `src/AC_FINDER.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ac_hint: Option<String>,
}

// ── Module loading ───────────────────────────────────────────────────────────────

/// Parse a `.ll` (text) or `.bc` (bitcode) file into a `Module`, dispatching
/// on file extension. Anything not ending in `.bc` is treated as text IR.
pub fn load_module(path: &Path) -> Result<Module, Box<dyn std::error::Error>> {
    let is_bitcode = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("bc"))
        .unwrap_or(false);
    let result = if is_bitcode {
        Module::from_bc_path(path)
    } else {
        Module::from_ir_path(path)
    };
    result.map_err(|e| format!("failed to parse LLVM IR at {}: {}", path.display(), e).into())
}

// ── Matching ──────────────────────────────────────────────────────────────────

struct Matcher {
    strategy: &'static str,
    pattern: Regex,
}

/// Build per-signature regex matchers against a demangled callee name (with
/// a synthetic trailing `(` appended, so the same anchor shape as
/// `ac_finder::make_matchers` applies). Duplicated rather than shared so
/// this module stays independently testable and doesn't depend on
/// `ac_finder`'s private matcher type -- same rationale as
/// `ac_finder::strip_turbofish` being duplicated from `llm_api_finder`.
fn make_matchers(sig: &AcSignature) -> Vec<Matcher> {
    let parts: Vec<&str> = sig.fn_name.split("::").collect();
    let method = parts.last().copied().unwrap_or("");
    let struct_path = if parts.len() > 1 {
        parts[..parts.len() - 1].join("::")
    } else {
        String::new()
    };

    let mut matchers = Vec::new();

    // 1. Direct:  jsonwebtoken::decode(
    let direct_pat = format!(r"^{}\s*\(", regex::escape(&sig.fn_name));
    if let Ok(re) = Regex::new(&direct_pat) {
        matchers.push(Matcher { strategy: "direct", pattern: re });
    }

    // 2. Angle-bracket:  <casbin::Enforcer as casbin::CoreApi>::enforce(
    // Match on the trait/type's last path segment appearing anywhere inside
    // the angle brackets, since the concrete `Self` type on the left of
    // `as` varies per call site and isn't known statically from the
    // catalogue entry -- only the trait name after `as` is fixed.
    if !struct_path.is_empty() {
        let struct_last: &str = struct_path.rsplit("::").next().unwrap_or_default();
        let ab_pat = format!(
            r"^<[^>]*{}[^>]*>\s*::\s*{}\s*\(",
            regex::escape(struct_last),
            regex::escape(method)
        );
        if let Ok(re) = Regex::new(&ab_pat) {
            matchers.push(Matcher { strategy: "angle-bracket", pattern: re });
        }
    }

    // 3. Short-name:  Enforcer::enforce(  (last two path segments -- lower confidence)
    if parts.len() >= 2 {
        let last_two = parts[parts.len() - 2..].join("::");
        let short_pat = format!(r"{}\s*\(", regex::escape(&last_two));
        if let Ok(re) = Regex::new(&short_pat) {
            matchers.push(Matcher { strategy: "short-name", pattern: re });
        }
    }

    matchers
}

/// Strip `::<...>` turbofish/generic-instantiation segments from a
/// demangled name, including nested generics -- same algorithm as
/// `ac_finder::strip_turbofish`, duplicated for the same reason as
/// `make_matchers` above. v0-mangled symbols can carry monomorphized type
/// arguments through to the demangled name; legacy mangling never does. The
/// legacy/v0 default has changed across `rustc` versions, so this function
/// has to handle both regardless of which one the target was built with.
fn strip_generics(s: &str) -> String {
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

/// Pull the callee's mangled name out of a `call` target operand. Returns
/// `None` for indirect calls (function pointers, vtable dispatch) -- the
/// callee is a `LocalOperand` there, not a `GlobalReference`, so there's no
/// static name to match against the catalogue. Same blind spot as
/// trait-object dispatch in `ac_finder`/`ac_finder_rs_src`.
fn callee_name(op: &Operand) -> Option<String> {
    let Operand::ConstantOperand(cref) = op else {
        return None;
    };
    match cref.as_ref() {
        Constant::GlobalReference { name, .. } => Some(match name {
            Name::Name(n) => (**n).clone(),
            Name::Number(n) => n.to_string(),
        }),
        _ => None,
    }
}

// ── Scanner ───────────────────────────────────────────────────────────────────

/// Scan a parsed `Module` for calls matching any of `sigs`. Walks every
/// defined function's basic blocks in order; declared-but-not-defined
/// functions have no body to scan (as expected -- they're callees, not call
/// sites, from this module's point of view).
pub fn scan_ac_llvm(module: &Module, sigs: &[AcSignature]) -> Vec<AcLlvmMatch> {
    let sig_matchers: Vec<(&AcSignature, Vec<Matcher>)> =
        sigs.iter().map(|sig| (sig, make_matchers(sig))).collect();

    let mut matches = Vec::new();

    for func in &module.functions {
        // Demangle the caller too -- `func.name` is the raw LLVM linkage
        // name (always mangled for a Rust function), and reporting that
        // verbatim would be far less readable than what
        // `ac_finder`/`ac_finder_rs_src` report for `callsite.function`.
        let func_display_name = strip_generics(&format!("{:#}", rustc_demangle::demangle(&func.name)));
        for block in &func.basic_blocks {
            let block_name = block.name.to_string();
            for (idx, instr) in block.instrs.iter().enumerate() {
                let Instruction::Call(call) = instr else {
                    continue;
                };
                let Some(target) = call.function.as_ref().right() else {
                    continue; // inline assembly -- no symbol to match
                };
                let Some(mangled) = callee_name(target) else {
                    continue; // indirect call -- no static callee name
                };
                // Alternate ({:#}) form, not default -- rustc_demangle shows
                // the trailing `::h<hash>` legacy-mangling hash segment by
                // default and *hides* it only under alternate formatting
                // (the reverse of what the name suggests). Catalog entries
                // are plain paths with no hash, so this is the form that
                // actually lines up with them.
                let demangled = strip_generics(&format!("{:#}", rustc_demangle::demangle(&mangled)));
                let probe = format!("{demangled}(");

                'sig: for (sig, matchers) in &sig_matchers {
                    for matcher in matchers {
                        if matcher.pattern.is_match(&probe) {
                            let debugloc = instr.get_debug_loc();
                            // Always None for now -- see the `ac_hint` doc
                            // comment on `AcLlvmMatch` for why.
                            let ac_hint = None;
                            matches.push(AcLlvmMatch {
                                library: sig.library.clone(),
                                fn_name: sig.fn_name.clone(),
                                category: sig.category.clone(),
                                match_strategy: matcher.strategy.to_string(),
                                callsite: AcLlvmCallSite {
                                    function: func_display_name.clone(),
                                    block: block_name.clone(),
                                    instruction_index: idx,
                                    file: debugloc.as_ref().map(|d| d.filename.clone()),
                                    line: debugloc.as_ref().map(|d| d.line),
                                },
                                mangled_name: mangled.clone(),
                                demangled_name: demangled.clone(),
                                ac_hint,
                            });
                            break 'sig;
                        }
                    }
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
    fn strip_generics_removes_turbofish() {
        assert_eq!(
            strip_generics("jsonwebtoken::decode::<my_app::Claims>"),
            "jsonwebtoken::decode"
        );
    }

    #[test]
    fn strip_generics_leaves_plain_path_alone() {
        assert_eq!(strip_generics("casbin::CoreApi::enforce"), "casbin::CoreApi::enforce");
    }

    #[test]
    fn callee_name_none_for_local_operand() {
        // Indirect call target (function pointer): a LocalOperand, not a
        // GlobalReference, so there's no static name to extract.
        let op = Operand::LocalOperand {
            name: Name::Number(0),
            ty: llvm_ir::types::Types::blank_for_testing().pointer(),
        };
        assert_eq!(callee_name(&op), None);
    }

    #[test]
    fn detects_direct_call_by_demangled_name() {
        let mir_style_probe = "jsonwebtoken::decode(";
        let s = sig("jsonwebtoken", "jsonwebtoken::decode", "authentication");
        let matchers = make_matchers(&s);
        assert!(matchers.iter().any(|m| m.pattern.is_match(mir_style_probe)));
    }

    #[test]
    fn detects_trait_method_via_angle_bracket_strategy() {
        let probe = "<casbin::Enforcer as casbin::CoreApi>::enforce(";
        let s = sig("casbin-rs", "casbin::CoreApi::enforce", "policy-enforcement");
        let matchers = make_matchers(&s);
        assert!(
            matchers
                .iter()
                .any(|m| m.strategy == "angle-bracket" && m.pattern.is_match(probe)),
            "expected an angle-bracket matcher to fire on {probe}"
        );
    }

    #[test]
    fn end_to_end_scan_finds_jsonwebtoken_decode() {
        // Real symbols captured from an actual `rustc --emit=llvm-ir`
        // build (see examples/src/ac_demo_llvm/), hash suffix and all --
        // deliberately NOT hash-free like the doctest-style symbols in the
        // other tests below. This is a regression guard for a real bug: the
        // scanner used to demangle with the *default* (non-alternate)
        // `Display` impl, which -- counter-intuitively -- SHOWS the
        // `::h<hash>` legacy-mangling hash suffix; only the *alternate*
        // (`{:#}`) form hides it. That meant every real rustc-produced
        // symbol demangled to `jsonwebtoken::decode::h<16 hex digits>`
        // instead of `jsonwebtoken::decode`, which never matched the
        // catalogue -- caught only by testing against real compiler output
        // end-to-end, not hand-authored hash-free IR.
        const IR: &str = r#"
declare i32 @_ZN12jsonwebtoken6decode17hdd5a20d74b58ee6dE()

define i32 @_ZN6my_app12verify_token17h88e413fa7f3736c7E() {
entry:
  %1 = call i32 @_ZN12jsonwebtoken6decode17hdd5a20d74b58ee6dE()
  ret i32 %1
}
"#;
        let module = Module::from_ir_str(IR).expect("valid IR");
        let sigs = vec![sig("jsonwebtoken", "jsonwebtoken::decode", "authentication")];
        let matches = scan_ac_llvm(&module, &sigs);
        assert_eq!(matches.len(), 1, "matches: {matches:#?}");
        assert_eq!(matches[0].demangled_name, "jsonwebtoken::decode");
        assert_eq!(matches[0].mangled_name, "_ZN12jsonwebtoken6decode17hdd5a20d74b58ee6dE");
        assert_eq!(matches[0].callsite.function, "my_app::verify_token");
    }

    #[test]
    fn end_to_end_scan_finds_casbin_trait_impl_call() {
        // Also a real captured symbol (see the doc comment on the test
        // above) -- exercises the `angle-bracket` strategy against a real
        // trait-impl call site, not just a literal probe string.
        const IR: &str = r#"
declare zeroext i1 @"_ZN52_$LT$casbin..Enforcer$u20$as$u20$casbin..CoreApi$GT$7enforce17h881d5c680406215aE"(ptr, ptr, i64, ptr, i64, ptr, i64)

define zeroext i1 @_ZN6my_app16check_permission17h9f9bc29708855812E(ptr %enforcer, ptr %sub.0, i64 %sub.1, ptr %obj.0, i64 %obj.1, ptr %act.0, i64 %act.1) {
entry:
  %r = call zeroext i1 @"_ZN52_$LT$casbin..Enforcer$u20$as$u20$casbin..CoreApi$GT$7enforce17h881d5c680406215aE"(ptr %enforcer, ptr %sub.0, i64 %sub.1, ptr %obj.0, i64 %obj.1, ptr %act.0, i64 %act.1)
  ret i1 %r
}
"#;
        let module = Module::from_ir_str(IR).expect("valid IR");
        let sigs = vec![sig("casbin-rs", "casbin::CoreApi::enforce", "policy-enforcement")];
        let matches = scan_ac_llvm(&module, &sigs);
        assert_eq!(matches.len(), 1, "matches: {matches:#?}");
        assert_eq!(matches[0].match_strategy, "angle-bracket");
        assert_eq!(matches[0].demangled_name, "<casbin::Enforcer as casbin::CoreApi>::enforce");
        assert_eq!(matches[0].callsite.function, "my_app::check_permission");
    }

    #[test]
    fn no_false_positive_on_unrelated_call() {
        // `_ZN5alloc6string6String3newE` -> "alloc::string::String::new"
        const IR: &str = r#"
declare i32 @_ZN5alloc6string6String3newE()

define void @main() {
entry:
  %1 = call i32 @_ZN5alloc6string6String3newE()
  ret void
}
"#;
        let module = Module::from_ir_str(IR).expect("valid IR");
        let sigs = vec![sig("jsonwebtoken", "jsonwebtoken::decode", "authentication")];
        let matches = scan_ac_llvm(&module, &sigs);
        assert!(matches.is_empty(), "false positive: {matches:#?}");
    }
}
