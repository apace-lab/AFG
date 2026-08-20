use afg::ac_finder::load_ac_signatures;
use afg::ac_finder_llvm::{load_module, scan_ac_llvm, AcLlvmMatch};
use clap::Parser;
use std::collections::BTreeMap;
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

    /// Base directory to write results into. Matches are grouped by
    /// AcSignature category (authentication | authorization |
    /// policy-enforcement | raw-http) and each group is written as its own
    /// JSON file under <out-dir>/<category>/<ir-file-stem>.json.
    #[arg(long, default_value = "ll_parser/signatures")]
    out_dir: PathBuf,
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

    let ir_file = args.ir.display().to_string();
    let ir_stem = args
        .ir
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "module".to_string());

    let mut by_category: BTreeMap<&str, Vec<&AcLlvmMatch>> = BTreeMap::new();
    for m in &matches {
        by_category.entry(m.category.as_str()).or_default().push(m);
    }

    for (category, cat_matches) in &by_category {
        let category_dir = args.out_dir.join(category);
        fs::create_dir_all(&category_dir)?;
        let out_file = category_dir.join(format!("{ir_stem}.json"));
        let result = serde_json::json!({
            "ir_file": ir_file,
            "category": category,
            "signatures_loaded": sigs.len(),
            "total_matches": cat_matches.len(),
            "matches": cat_matches,
        });
        fs::write(&out_file, serde_json::to_string_pretty(&result)?)?;
        eprintln!("[find_ac_points_llvm] {} {} match(es) written to {}", cat_matches.len(), category, out_file.display());
    }
    if by_category.is_empty() {
        eprintln!("[find_ac_points_llvm] no matches -- nothing written under {}", args.out_dir.display());
    }

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
