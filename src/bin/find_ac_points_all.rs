//! Pipeline entry point: runs the Rust MIR scanner (`find_ac_points`), the
//! Rust source scanner (`find_ac_points_src`), the JS/TS source scanner
//! (`find_ac_points_js`), and — when built with `--features llvm-ir-scan` —
//! the real-LLVM-IR scanner (`find_ac_points_llvm`) in one pass, merging all
//! of them into a single report. Mirrors `find_llm_calls_all`'s role for the
//! AC finder — the "whole app" view for a mixed Rust+frontend target.

use afg::ac_finder::{load_ac_signatures, scan_ac_mir, AcMatch};
use afg::ac_finder_js::{load_ac_js_signatures, scan_ac_path, AcScanOptions, JsAcMatch};
#[cfg(feature = "llvm-ir-scan")]
use afg::ac_finder_llvm::{load_module, scan_ac_llvm, AcLlvmMatch};
use afg::ac_finder_rs_src::{scan_ac_rs_path, AcRsMatch, AcRsScanOptions};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_ac_points_all",
    about = "Run find_ac_points (Rust MIR), find_ac_points_src (Rust source), find_ac_points_js (JS/TS source), and (with --features llvm-ir-scan) find_ac_points_llvm (LLVM IR), merging the results"
)]
struct Args {
    /// Path to the RUPTA MIR dump (.txt). Omit to skip the Rust-MIR scan.
    #[arg(long)]
    mir: Option<PathBuf>,

    /// Rust source file or directory to scan directly (no MIR dump needed).
    /// Omit to skip the Rust-source scan.
    #[arg(long)]
    rs_src: Option<PathBuf>,

    /// JS/TS source file or directory. Omit to skip the JS/TS-side scan.
    #[arg(long)]
    src: Option<PathBuf>,

    /// Real LLVM IR module (.ll or .bc) to scan. Omit to skip the LLVM-IR
    /// scan. Only usable when this binary was built with
    /// `--features llvm-ir-scan`; passing it otherwise is a hard error.
    #[arg(long)]
    llvm_ir: Option<PathBuf>,

    /// Directory containing ac_functions.json and ac_functions_js.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write merged results as JSON to this file
    #[arg(long, default_value = "ac_matches_all.json")]
    out: PathBuf,

    /// Forwarded to find_ac_points_js: report every fetch()/axios()/http(s).request()
    /// call, even without a known access-control path nearby.
    #[arg(long)]
    all_http_calls: bool,

    /// Forwarded to find_ac_points_js: also scan node_modules.
    #[arg(long)]
    include_node_modules: bool,

    /// Forwarded to find_ac_points_src: also scan target/.
    #[arg(long)]
    include_target_dir: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.mir.is_none() && args.rs_src.is_none() && args.src.is_none() && args.llvm_ir.is_none() {
        return Err("at least one of --mir, --rs-src, --src, or --llvm-ir is required".into());
    }
    #[cfg(not(feature = "llvm-ir-scan"))]
    if args.llvm_ir.is_some() {
        return Err(
            "--llvm-ir requires this binary to be built with --features llvm-ir-scan (needs LLVM installed; see src/AC_FINDER.md#scanning-real-llvm-ir)"
                .into(),
        );
    }

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    // ── Stage 1: Rust MIR scan (find_ac_points) ──
    let rust_matches: Vec<AcMatch> = if let Some(mir_path) = &args.mir {
        let sigs = load_ac_signatures(&datasets_path)?;
        eprintln!(
            "[find_ac_points_all] [rust] loaded {} signatures from {}",
            sigs.len(),
            datasets_path.join("ac_functions.json").display()
        );
        let mir_content = fs::read_to_string(mir_path)
            .map_err(|e| format!("cannot read {}: {}", mir_path.display(), e))?;
        let matches = scan_ac_mir(&mir_content, &sigs);
        println!("[rust]  {} call site(s) found in {}", matches.len(), mir_path.display());
        for m in &matches {
            let cs = &m.callsite;
            println!(
                "  Found {} [{}] call ({}) at {} ({}) / {} [line {}]",
                m.library, m.category, m.fn_name, cs.func_id, cs.function, cs.basic_block, cs.line
            );
            if let Some(hint) = &m.ac_hint {
                println!("    ac hint: {hint}");
            }
        }
        matches
    } else {
        eprintln!("[find_ac_points_all] [rust] skipped (no --mir given)");
        Vec::new()
    };

    // ── Stage 2: Rust source scan (find_ac_points_src), no MIR dump needed ──
    let rs_src_matches: Vec<AcRsMatch> = if let Some(rs_src_path) = &args.rs_src {
        let sigs = load_ac_signatures(&datasets_path)?;
        eprintln!(
            "[find_ac_points_all] [rs-src] loaded {} signatures from {}",
            sigs.len(),
            datasets_path.join("ac_functions.json").display()
        );
        let opts = AcRsScanOptions {
            all_http_calls: args.all_http_calls,
            include_target_dir: args.include_target_dir,
            ..Default::default()
        };
        let matches = scan_ac_rs_path(rs_src_path, &sigs, &opts)
            .map_err(|e| format!("cannot scan {}: {}", rs_src_path.display(), e))?;
        println!("[rs-src] {} call site(s) found in {}", matches.len(), rs_src_path.display());
        for m in &matches {
            let cs = &m.callsite;
            println!(
                "  Found {} [{}] call ({}) in fn {} at {}:{} [{}]",
                m.library, m.category, m.fn_name, cs.function, cs.file, cs.line, m.match_strategy
            );
            if let Some(hint) = &m.ac_hint {
                println!("    ac hint: {hint}");
            }
        }
        matches
    } else {
        eprintln!("[find_ac_points_all] [rs-src] skipped (no --rs-src given)");
        Vec::new()
    };

    // ── Stage 3: JS/TS source scan (find_ac_points_js), run after stage 2 ──
    let js_matches: Vec<JsAcMatch> = if let Some(src_path) = &args.src {
        let sigs = load_ac_js_signatures(&datasets_path)?;
        eprintln!(
            "[find_ac_points_all] [js]   loaded {} signatures from {}",
            sigs.len(),
            datasets_path.join("ac_functions_js.json").display()
        );
        let opts = AcScanOptions {
            all_http_calls: args.all_http_calls,
            include_node_modules: args.include_node_modules,
        };
        let matches = scan_ac_path(src_path, &sigs, &opts)
            .map_err(|e| format!("cannot scan {}: {}", src_path.display(), e))?;
        println!("[js]    {} call site(s) found in {}", matches.len(), src_path.display());
        for m in &matches {
            let cs = &m.callsite;
            println!(
                "  Found {} [{}] call ({}, {}) at {}:{} [{}]",
                m.library, m.category, m.pattern, m.kind, cs.file, cs.line, m.match_strategy
            );
            if let Some(hint) = &m.ac_hint {
                println!("    ac hint: {hint}");
            }
        }
        matches
    } else {
        eprintln!("[find_ac_points_all] [js]   skipped (no --src given)");
        Vec::new()
    };

    // ── Stage 4: real LLVM IR scan (find_ac_points_llvm), --features llvm-ir-scan only ──
    #[cfg(feature = "llvm-ir-scan")]
    let llvm_matches: Vec<AcLlvmMatch> = if let Some(ir_path) = &args.llvm_ir {
        let sigs = load_ac_signatures(&datasets_path)?;
        eprintln!(
            "[find_ac_points_all] [llvm] loaded {} signatures from {}",
            sigs.len(),
            datasets_path.join("ac_functions.json").display()
        );
        let module = load_module(ir_path)?;
        let matches = scan_ac_llvm(&module, &sigs);
        println!("[llvm]  {} call site(s) found in {}", matches.len(), ir_path.display());
        for m in &matches {
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
        matches
    } else {
        eprintln!("[find_ac_points_all] [llvm] skipped (no --llvm-ir given)");
        Vec::new()
    };
    #[cfg(not(feature = "llvm-ir-scan"))]
    let llvm_matches: Vec<serde_json::Value> = Vec::new();

    let total =
        rust_matches.len() + rs_src_matches.len() + js_matches.len() + llvm_matches.len();
    println!(
        "\nTotal: {total} access-control call site(s) across all scans ({} rust-mir, {} rust-src, {} js, {} llvm-ir)",
        rust_matches.len(),
        rs_src_matches.len(),
        js_matches.len(),
        llvm_matches.len()
    );

    let result = serde_json::json!({
        "mir": args.mir.map(|p| p.display().to_string()),
        "rs_src": args.rs_src.map(|p| p.display().to_string()),
        "src": args.src.map(|p| p.display().to_string()),
        "llvm_ir": args.llvm_ir.map(|p| p.display().to_string()),
        "rust_matches": rust_matches,
        "rust_src_matches": rs_src_matches,
        "js_matches": js_matches,
        "llvm_matches": llvm_matches,
        "total_matches": total,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!("[find_ac_points_all] JSON written to {}", args.out.display());

    Ok(())
}
