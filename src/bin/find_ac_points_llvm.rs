use afg::ac_finder::load_ac_signatures;
use afg::ac_finder_llvm::{load_module, scan_ac_llvm, AcLlvmMatch};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_ac_points_llvm",
    about = "Scan a real LLVM IR module (.ll or .bc) for access-control (authn/authz) call sites"
)]
struct Args {
    /// Path to the LLVM IR module: text IR (.ll) or bitcode (.bc)
    #[arg(long)]
    ir: PathBuf,

    /// Directory containing ac_functions.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write results as JSON to this file
    #[arg(long, default_value = "ac_matches_llvm.json")]
    out: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    let sigs = load_ac_signatures(&datasets_path)?;
    eprintln!(
        "[find_ac_points_llvm] loaded {} signatures from {}",
        sigs.len(),
        datasets_path.join("ac_functions.json").display()
    );

    let module = load_module(&args.ir)?;
    let matches = scan_ac_llvm(&module, &sigs);

    print_summary(&args.ir.display().to_string(), &matches);

    let result = serde_json::json!({
        "ir_file": args.ir.display().to_string(),
        "signatures_loaded": sigs.len(),
        "total_matches": matches.len(),
        "matches": matches,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!("[find_ac_points_llvm] JSON written to {}", args.out.display());

    Ok(())
}

fn print_summary(ir_file: &str, matches: &[AcLlvmMatch]) {
    if matches.is_empty() {
        println!("No access-control call sites found in {ir_file}");
        return;
    }
    println!("Found {} access-control call site(s) in {ir_file}:\n", matches.len());
    for m in matches {
        let cs = &m.callsite;
        let loc = match (&cs.file, cs.line) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            _ => format!("{} / instr #{}", cs.block, cs.instruction_index),
        };
        println!(
            "  Found {} [{}] call ({}) in {} at {} [{}]",
            m.library, m.category, m.fn_name, cs.function, loc, m.match_strategy
        );
        if let Some(hint) = &m.ac_hint {
            println!("    ac hint: {hint}");
        }
    }
}
