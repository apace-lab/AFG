//! Regression tests that run the built `find_ac_points*` binaries against
//! the worked-example fixtures in `examples/` and check the JSON output.
//! These exist so a future change that silently drifts from what those
//! fixtures demonstrate fails `cargo test` instead of only being caught by
//! someone manually diffing output by hand.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique output path per call -- tests run in parallel and several call
/// `run()` more than once against the same binary, so a name derived only
/// from the binary/process would race across test threads.
fn tmp_out(name: &str) -> PathBuf {
    let base = PathBuf::from(name);
    let basename = base.file_name().and_then(|n| n.to_str()).unwrap_or(name);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("afg_fixture_test_{}_{}_{}.json", std::process::id(), basename, n))
}

fn run(bin_exe: &str, args: &[&str]) -> Value {
    let out_path = tmp_out(bin_exe);
    let mut full_args: Vec<&str> = args.to_vec();
    full_args.push("--out");
    let out_str = out_path.to_str().unwrap();
    full_args.push(out_str);

    let status = Command::new(bin_exe)
        .args(&full_args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {bin_exe}: {e}"));
    assert!(status.success(), "{bin_exe} {full_args:?} exited with {status}");

    let content = std::fs::read_to_string(&out_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", out_path.display()));
    std::fs::remove_file(&out_path).ok();
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse JSON from {bin_exe}: {e}"))
}

/// Extract `(library, match_strategy)` pairs from a report's `matches`
/// array, order-independent — call order between the call-shape pass and
/// the bare-reference pass in `find_ac_points_js` isn't a contract worth
/// pinning down here.
fn lib_strategy_pairs(report: &Value) -> Vec<(String, String)> {
    report["matches"]
        .as_array()
        .expect("matches should be an array")
        .iter()
        .map(|m| {
            (
                m["library"].as_str().unwrap_or_default().to_string(),
                m["match_strategy"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn assert_contains_pair(pairs: &[(String, String)], library: &str, strategy: &str) {
    assert!(
        pairs.iter().any(|(l, s)| l == library && s == strategy),
        "expected a ({library}, {strategy}) match, got: {pairs:?}"
    );
}

/// `examples/ac_demo_mir.txt` -- hand-written MIR-shaped text (not a real
/// RUPTA dump) exercising every AC library, every category, and all 3 MIR
/// match strategies (`direct`, `angle-bracket`, `short-name`) in one file.
#[test]
fn ac_demo_mir_matches_worked_example() {
    let report = run(env!("CARGO_BIN_EXE_find_ac_points"), &["--mir", "examples/ac_demo_mir.txt"]);
    assert_eq!(report["total_matches"], 15);
    assert_eq!(report["signatures_loaded"], 25);

    let pairs = lib_strategy_pairs(&report);
    assert_contains_pair(&pairs, "actix-web-httpauth", "direct");
    assert_contains_pair(&pairs, "actix-web-grants", "short-name");
    assert_contains_pair(&pairs, "actix-identity", "direct");
    assert_contains_pair(&pairs, "axum-login", "direct");
    assert_contains_pair(&pairs, "tower-http-auth", "direct");
    assert_contains_pair(&pairs, "jsonwebtoken", "direct");
    assert_contains_pair(&pairs, "casbin-rs", "angle-bracket");
    assert_contains_pair(&pairs, "oso", "direct");
    assert_contains_pair(&pairs, "biscuit-auth", "direct");
    assert_contains_pair(&pairs, "ldap3", "direct");
    assert_contains_pair(&pairs, "oauth2", "direct");
    assert_contains_pair(&pairs, "bcrypt", "direct");
    assert_contains_pair(&pairs, "argon2", "direct");

    // find_ac_points has no --all-http-calls suppression -- both the hinted
    // (introspect_token) and unhinted (ping_health) raw-http-authz calls are
    // reported unconditionally, unlike find_ac_points_src/_js.
    let raw_http: Vec<&Value> = report["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["library"] == "raw-http-authz")
        .collect();
    assert_eq!(raw_http.len(), 2, "expected both raw-http-authz call sites: {raw_http:#?}");
    assert!(
        raw_http.iter().any(|m| m["ac_hint"] == "OAuth2 token introspection (RFC 7662)"),
        "expected introspect_token's hinted match: {raw_http:#?}"
    );
    assert!(
        raw_http.iter().any(|m| m["ac_hint"].is_null()),
        "expected ping_health's unhinted match: {raw_http:#?}"
    );
}

/// `examples/src/ac_demo.rs` -- exercises every AC library, category, and
/// source-scan match strategy (`direct`, `method`, `short-name`,
/// `type-method`, `http+path-hint`/`http-call-only`) that `find_ac_points_src`
/// supports.
#[test]
fn ac_demo_src_matches_worked_example() {
    let report = run(env!("CARGO_BIN_EXE_find_ac_points_src"), &["--src", "examples/src/ac_demo.rs"]);
    assert_eq!(report["total_matches"], 11);
    assert_eq!(report["signatures_loaded"], 25);

    let pairs = lib_strategy_pairs(&report);
    assert_contains_pair(&pairs, "actix-web-httpauth", "type-method");
    assert_contains_pair(&pairs, "actix-web-grants", "method");
    assert_contains_pair(&pairs, "actix-identity", "method");
    assert_contains_pair(&pairs, "axum-login", "method");
    assert_contains_pair(&pairs, "tower-http-auth", "type-method");
    assert_contains_pair(&pairs, "jsonwebtoken", "direct");
    assert_contains_pair(&pairs, "jsonwebtoken", "short-name");
    assert_contains_pair(&pairs, "casbin-rs", "method");
    assert_contains_pair(&pairs, "oso", "method");
    assert_contains_pair(&pairs, "biscuit-auth", "method");
    assert_contains_pair(&pairs, "raw-http-authz", "http+path-hint");
}

/// `ping_health`'s unhinted `.send()` is suppressed by default, but shows up
/// with `--all-http-calls`.
#[test]
fn ac_demo_src_all_http_calls_adds_one_more_match() {
    let default_report =
        run(env!("CARGO_BIN_EXE_find_ac_points_src"), &["--src", "examples/src/ac_demo.rs"]);
    let all_report = run(
        env!("CARGO_BIN_EXE_find_ac_points_src"),
        &["--src", "examples/src/ac_demo.rs", "--all-http-calls"],
    );
    let default_total = default_report["total_matches"].as_i64().unwrap();
    let all_total = all_report["total_matches"].as_i64().unwrap();
    assert_eq!(all_total, default_total + 1);
}

/// `examples/src/ac_demo_js.ts` -- exercises every AC library, category, and
/// match strategy (`call+import`, `call-only`, `reference`,
/// `reference+import`, `http+path-hint`/`http-call-only`) that
/// `find_ac_points_js` supports.
#[test]
fn ac_demo_js_matches_worked_example() {
    let report = run(env!("CARGO_BIN_EXE_find_ac_points_js"), &["--src", "examples/src/ac_demo_js.ts"]);
    assert_eq!(report["total_matches"], 16);
    assert_eq!(report["signatures_loaded"], 39);

    let pairs = lib_strategy_pairs(&report);
    assert_contains_pair(&pairs, "passport", "call+import");
    assert_contains_pair(&pairs, "passport", "reference+import");
    assert_contains_pair(&pairs, "jsonwebtoken", "call+import");
    assert_contains_pair(&pairs, "express-jwt", "call+import");
    assert_contains_pair(&pairs, "nestjs-authz", "call+import");
    assert_contains_pair(&pairs, "casl", "call+import");
    assert_contains_pair(&pairs, "casbin-node", "call+import");
    assert_contains_pair(&pairs, "next-auth", "call+import");
    assert_contains_pair(&pairs, "firebase-admin-auth", "call+import");
    assert_contains_pair(&pairs, "auth0", "call+import");
    assert_contains_pair(&pairs, "connect-ensure-login", "call+import");
    assert_contains_pair(&pairs, "generic-authz-checks", "call-only");
    assert_contains_pair(&pairs, "generic-authz-checks", "reference");
    assert_contains_pair(&pairs, "raw-http-authz", "http+path-hint");
}

/// `pingHealth`'s unhinted `fetch()` is suppressed by default, but shows up
/// with `--all-http-calls`.
#[test]
fn ac_demo_js_all_http_calls_adds_one_more_match() {
    let default_report =
        run(env!("CARGO_BIN_EXE_find_ac_points_js"), &["--src", "examples/src/ac_demo_js.ts"]);
    let all_report = run(
        env!("CARGO_BIN_EXE_find_ac_points_js"),
        &["--src", "examples/src/ac_demo_js.ts", "--all-http-calls"],
    );
    let default_total = default_report["total_matches"].as_i64().unwrap();
    let all_total = all_report["total_matches"].as_i64().unwrap();
    assert_eq!(all_total, default_total + 1);
}

/// Regression test for the `function requireRole(...)`-declaration false
/// positive fixed in `ac_finder_js.rs::is_fn_declaration` -- a bare
/// declaration sharing a catalogue pattern's name must not be reported.
#[test]
fn js_fn_declaration_sharing_a_pattern_name_is_not_reported() {
    let dir = std::env::temp_dir().join(format!("afg_fixture_test_fndecl_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src_path = dir.join("guards.ts");
    std::fs::write(
        &src_path,
        r#"
function requireRole(role) {
  return function (req, res, next) {
    next();
  };
}
"#,
    )
    .unwrap();

    let report = run(env!("CARGO_BIN_EXE_find_ac_points_js"), &["--src", src_path.to_str().unwrap()]);
    assert_eq!(report["total_matches"], 0, "declaration should not be reported: {report:#?}");

    std::fs::remove_dir_all(&dir).ok();
}

/// `examples/ac_demo_llvm.ll` -- real `rustc --emit=llvm-ir` output (see
/// `src/AC_FINDER.md#regenerating-examplesac_demo_llvmll` for how it was
/// generated), exercising the `direct` and `angle-bracket` match strategies
/// against a real trait-impl call site. Only runs when built with
/// `--features llvm-ir-scan` -- `find_ac_points_llvm` doesn't exist
/// otherwise (see `required-features` in Cargo.toml), and referencing
/// `CARGO_BIN_EXE_find_ac_points_llvm` without the feature would fail to
/// compile.
#[cfg(feature = "llvm-ir-scan")]
#[test]
fn ac_demo_llvm_matches_worked_example() {
    let report = run(env!("CARGO_BIN_EXE_find_ac_points_llvm"), &["--ir", "examples/ac_demo_llvm.ll"]);
    assert_eq!(report["total_matches"], 3);
    assert_eq!(report["signatures_loaded"], 25);

    let pairs = lib_strategy_pairs(&report);
    assert_contains_pair(&pairs, "jsonwebtoken", "direct");
    assert_contains_pair(&pairs, "bcrypt", "direct");
    assert_contains_pair(&pairs, "casbin-rs", "angle-bracket");
}
