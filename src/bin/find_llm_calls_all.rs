//! Pipeline entry point: runs the Rust MIR scanner (`find_llm_calls`) and
//! then the JS/TS source scanner (`find_llm_calls_js`) in one pass, merging
//! both into a single report. This is the "whole app" view for a mixed
//! Rust+frontend target (e.g. Tauri): Rust-side LLM calls come from RUPTA's
//! MIR dump, JS/TS-side calls come directly from source since RUPTA can't
//! see them at all. Either input is optional so this also works as a
//! Rust-only or JS-only scan.

use afg::llm_api_finder::{load_signatures, scan_mir, ApiMatch};
use afg::llm_api_finder_js::{load_js_signatures, scan_path, JsApiMatch, ScanOptions};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "find_llm_calls_all",
    about = "Run find_llm_calls (Rust MIR) then find_llm_calls_js (JS/TS source) and merge the results"
)]
struct Args {
    /// Path to the RUPTA MIR dump (.txt). Omit to skip the Rust-side scan.
    #[arg(long)]
    mir: Option<PathBuf>,

    /// JS/TS source file or directory. Omit to skip the JS/TS-side scan.
    #[arg(long)]
    src: Option<PathBuf>,

    /// Directory containing llm_api_functions.json and llm_api_functions_js.json
    /// (defaults to <crate-root>/datasets/)
    #[arg(long)]
    datasets: Option<PathBuf>,

    /// Write merged results as JSON to this file
    #[arg(long, default_value = "llm_api_matches_all.json")]
    out: PathBuf,

    /// Forwarded to find_llm_calls_js: report every fetch()/axios()/http(s).request()
    /// call, even without a known LLM path nearby.
    #[arg(long)]
    all_http_calls: bool,

    /// Forwarded to find_llm_calls_js: also scan node_modules.
    #[arg(long)]
    include_node_modules: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.mir.is_none() && args.src.is_none() {
        return Err("at least one of --mir or --src is required".into());
    }

    let datasets_path = args
        .datasets
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    // ── Stage 1: Rust MIR scan (find_llm_calls) ──
    let rust_matches: Vec<ApiMatch> = if let Some(mir_path) = &args.mir {
        let sigs = load_signatures(&datasets_path)?;
        eprintln!(
            "[find_llm_calls_all] [rust] loaded {} signatures from {}",
            sigs.len(),
            datasets_path.join("llm_api_functions.json").display()
        );
        let mir_content = fs::read_to_string(mir_path)
            .map_err(|e| format!("cannot read {}: {}", mir_path.display(), e))?;
        let matches = scan_mir(&mir_content, &sigs);
        println!(
            "[rust]  {} call(s) found in {}",
            matches.len(),
            mir_path.display()
        );
        for m in &matches {
            let cs = &m.callsite;
            println!(
                "  Found {} API call ({}) at {} ({}) / {} [line {}]",
                m.library, m.fn_name, cs.func_id, cs.function, cs.basic_block, cs.line
            );
            if let Some(hint) = &m.provider_hint {
                println!("    provider hint: {hint}");
            }
        }
        matches
    } else {
        eprintln!("[find_llm_calls_all] [rust] skipped (no --mir given)");
        Vec::new()
    };

    // ── Stage 2: JS/TS source scan (find_llm_calls_js), run after stage 1 ──
    let js_matches: Vec<JsApiMatch> = if let Some(src_path) = &args.src {
        let sigs = load_js_signatures(&datasets_path)?;
        eprintln!(
            "[find_llm_calls_all] [js]   loaded {} signatures from {}",
            sigs.len(),
            datasets_path.join("llm_api_functions_js.json").display()
        );
        let opts = ScanOptions {
            all_http_calls: args.all_http_calls,
            include_node_modules: args.include_node_modules,
        };
        let matches = scan_path(src_path, &sigs, &opts)
            .map_err(|e| format!("cannot scan {}: {}", src_path.display(), e))?;
        println!(
            "[js]    {} call(s) found in {}",
            matches.len(),
            src_path.display()
        );
        for m in &matches {
            let cs = &m.callsite;
            println!(
                "  Found {} call ({}, {}) at {}:{} [{}]",
                m.library, m.pattern, m.kind, cs.file, cs.line, m.match_strategy
            );
            if let Some(hint) = &m.provider_hint {
                println!("    provider hint: {hint}");
            }
        }
        matches
    } else {
        eprintln!("[find_llm_calls_all] [js]   skipped (no --src given)");
        Vec::new()
    };

    let total = rust_matches.len() + js_matches.len();
    println!(
        "\nTotal: {total} LLM API call(s) across both scans ({} rust, {} js)",
        rust_matches.len(),
        js_matches.len()
    );

    let result = serde_json::json!({
        "mir": args.mir.map(|p| p.display().to_string()),
        "src": args.src.map(|p| p.display().to_string()),
        "rust_matches": rust_matches,
        "js_matches": js_matches,
        "total_matches": total,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    eprintln!(
        "[find_llm_calls_all] JSON written to {}",
        args.out.display()
    );

    Ok(())
}
