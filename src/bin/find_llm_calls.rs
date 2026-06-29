use afg::llm_api_finder::{load_signatures, scan_mir, ApiMatch};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_llm_calls",
    about = "Scan a rupta MIR dump for LLM API call sites"
)]
struct Args {
    /// Path to the rupta MIR dump (.txt)
    #[arg(long)]
    mir: PathBuf,

    /// Directory containing llm_api_functions.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write results as JSON to this file
    #[arg(long, default_value = "llm_api_matches.json")]
    out: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    // Re-parse JSON every invocation so users can update it without recompiling.
    let sigs = load_signatures(&datasets_path)?;
    eprintln!(
        "[find_llm_calls] loaded {} signatures from {}",
        sigs.len(),
        datasets_path.join("llm_api_functions.json").display()
    );

    let mir_content = fs::read_to_string(&args.mir)
        .map_err(|e| format!("cannot read {}: {}", args.mir.display(), e))?;

    let matches = scan_mir(&mir_content, &sigs);

    print_summary(&args.mir.display().to_string(), &matches);

    let result = serde_json::json!({
        "mir_file": args.mir.display().to_string(),
        "signatures_loaded": sigs.len(),
        "total_matches": matches.len(),
        "matches": matches,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!("[find_llm_calls] JSON written to {}", args.out.display());

    Ok(())
}

fn print_summary(mir_file: &str, matches: &[ApiMatch]) {
    if matches.is_empty() {
        println!("No LLM API calls found in {mir_file}");
        return;
    }
    println!("Found {} LLM API call(s) in {mir_file}:\n", matches.len());
    for m in matches {
        let cs = &m.callsite;
        println!(
            "  Found {} API call ({}) at {} ({}) / {} [line {}]",
            m.library, m.fn_name, cs.func_id, cs.function, cs.basic_block, cs.line
        );
    }
}
