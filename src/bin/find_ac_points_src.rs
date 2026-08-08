use afg::ac_finder::load_ac_signatures;
use afg::ac_finder_rs_src::{scan_ac_rs_path, AcRsMatch, AcRsScanOptions};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_ac_points_src",
    about = "Scan Rust *source* (.rs files) directly for access-control (authn/authz) call sites — no RUPTA MIR dump required (companion to find_ac_points, which scans a MIR dump)"
)]
struct Args {
    /// Path to a Rust source file or directory to scan
    #[arg(long)]
    src: PathBuf,

    /// Directory containing ac_functions.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write results as JSON to this file
    #[arg(long, default_value = "ac_matches_src.json")]
    out: PathBuf,

    /// Report every `.send(`-shaped call once `reqwest` is referenced in the
    /// file, even when no known access-control REST path suffix is found
    /// nearby. Off by default because reqwest is used for plenty of
    /// non-access-control HTTP calls.
    #[arg(long)]
    all_http_calls: bool,

    /// Also scan target/ (build output — off by default).
    #[arg(long)]
    include_target_dir: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    // Re-parse JSON every invocation so users can update it without recompiling.
    let sigs = load_ac_signatures(&datasets_path)?;
    eprintln!(
        "[find_ac_points_src] loaded {} signatures from {}",
        sigs.len(),
        datasets_path.join("ac_functions.json").display()
    );

    let opts = AcRsScanOptions {
        all_http_calls: args.all_http_calls,
        include_target_dir: args.include_target_dir,
        ..Default::default()
    };

    let matches = scan_ac_rs_path(&args.src, &sigs, &opts)
        .map_err(|e| format!("cannot scan {}: {}", args.src.display(), e))?;

    print_summary(&args.src.display().to_string(), &matches);

    let result = serde_json::json!({
        "src": args.src.display().to_string(),
        "signatures_loaded": sigs.len(),
        "total_matches": matches.len(),
        "matches": matches,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!("[find_ac_points_src] JSON written to {}", args.out.display());

    Ok(())
}

fn print_summary(src: &str, matches: &[AcRsMatch]) {
    if matches.is_empty() {
        println!("No access-control call sites found in {src}");
        return;
    }
    println!("Found {} access-control call site(s) in {src}:\n", matches.len());
    for m in matches {
        let cs = &m.callsite;
        println!(
            "  Found {} [{}] call ({}) in fn {} at {}:{} [{}]",
            m.library, m.category, m.fn_name, cs.function, cs.file, cs.line, m.match_strategy
        );
        if !m.parameters.is_empty() {
            println!("    parameters: {}", m.parameters.join(", "));
        }
        if let Some(hint) = &m.ac_hint {
            println!("    ac hint: {hint}");
        }
    }
}
