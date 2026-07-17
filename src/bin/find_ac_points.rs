use afg::ac_finder::{load_ac_signatures, scan_ac_mir, AcMatch};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_ac_points",
    about = "Scan a rupta MIR dump for access-control (authn/authz) call sites"
)]
struct Args {
    /// Path to the rupta MIR dump (.txt)
    #[arg(long)]
    mir: PathBuf,

    /// Directory containing ac_functions.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write results as JSON to this file
    #[arg(long, default_value = "ac_matches.json")]
    out: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    // Re-parse JSON every invocation so users can update it without recompiling.
    let sigs = load_ac_signatures(&datasets_path)?;
    eprintln!(
        "[find_ac_points] loaded {} signatures from {}",
        sigs.len(),
        datasets_path.join("ac_functions.json").display()
    );

    let mir_content = fs::read_to_string(&args.mir)
        .map_err(|e| format!("cannot read {}: {}", args.mir.display(), e))?;

    let matches = scan_ac_mir(&mir_content, &sigs);

    print_summary(&args.mir.display().to_string(), &matches);

    let result = serde_json::json!({
        "mir_file": args.mir.display().to_string(),
        "signatures_loaded": sigs.len(),
        "total_matches": matches.len(),
        "matches": matches,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!("[find_ac_points] JSON written to {}", args.out.display());

    Ok(())
}

fn print_summary(mir_file: &str, matches: &[AcMatch]) {
    if matches.is_empty() {
        println!("No access-control call sites found in {mir_file}");
        return;
    }
    println!("Found {} access-control call site(s) in {mir_file}:\n", matches.len());
    for m in matches {
        let cs = &m.callsite;
        println!(
            "  Found {} [{}] call ({}) at {} ({}) / {} [line {}]",
            m.library, m.category, m.fn_name, cs.func_id, cs.function, cs.basic_block, cs.line
        );
        if let Some(hint) = &m.ac_hint {
            println!("    ac hint: {hint}");
        }
    }
}
