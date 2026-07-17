use afg::ac_finder_js::{load_ac_js_signatures, scan_ac_path, AcScanOptions, JsAcMatch};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_ac_points_js",
    about = "Scan JS/TS source for access-control (authn/authz) call sites (companion to find_ac_points, which scans Rust MIR)"
)]
struct Args {
    /// Path to a JS/TS source file or directory to scan
    #[arg(long)]
    src: PathBuf,

    /// Directory containing ac_functions_js.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write results as JSON to this file
    #[arg(long, default_value = "ac_matches_js.json")]
    out: PathBuf,

    /// Report every fetch()/axios()/http(s).request() call, even when no
    /// known access-control REST path suffix is found nearby. Off by default
    /// because ordinary frontend code calls fetch() constantly for unrelated
    /// reasons.
    #[arg(long)]
    all_http_calls: bool,

    /// Also scan node_modules (off by default: vendored dependency source,
    /// not the target's own code).
    #[arg(long)]
    include_node_modules: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    let sigs = load_ac_js_signatures(&datasets_path)?;
    eprintln!(
        "[find_ac_points_js] loaded {} signatures from {}",
        sigs.len(),
        datasets_path.join("ac_functions_js.json").display()
    );

    let opts = AcScanOptions {
        all_http_calls: args.all_http_calls,
        include_node_modules: args.include_node_modules,
    };

    let matches = scan_ac_path(&args.src, &sigs, &opts)
        .map_err(|e| format!("cannot scan {}: {}", args.src.display(), e))?;

    print_summary(&args.src.display().to_string(), &matches);

    let result = serde_json::json!({
        "src": args.src.display().to_string(),
        "signatures_loaded": sigs.len(),
        "total_matches": matches.len(),
        "matches": matches,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!("[find_ac_points_js] JSON written to {}", args.out.display());

    Ok(())
}

fn print_summary(src: &str, matches: &[JsAcMatch]) {
    if matches.is_empty() {
        println!("No access-control call sites found in {src}");
        return;
    }
    println!("Found {} access-control call site(s) in {src}:\n", matches.len());
    for m in matches {
        let cs = &m.callsite;
        println!(
            "  Found {} [{}] call ({}, {}) at {}:{} [{}]",
            m.library, m.category, m.pattern, m.kind, cs.file, cs.line, m.match_strategy
        );
        if let Some(hint) = &m.ac_hint {
            println!("    ac hint: {hint}");
        }
    }
}
