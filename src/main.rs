//! afg: MUMP overlap detector post-pass over rupta's points-to dump.
//!
//! Consumes the text file produced by `cargo pta --dump-pts` together with a
//! MUMP user-config JSON.  For each configured user, computes the set of
//! abstract objects reachable from that user's seed locals via rupta's pts
//! relation, then reports abstract objects reached by two or more distinct
//! users; the Scoped Taint Pointer Analysis (STPA) cross-user overlap.

use clap::Parser;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "afg", about = "MUMP overlap detector over rupta's pts dump")]
struct Args {
    /// rupta's points-to dump (from `cargo pta --dump-pts <path>`)
    #[arg(long)]
    pts: PathBuf,
    /// MUMP user config JSON
    #[arg(long)]
    config: PathBuf,
    /// Print full per-user reachable sets (noisy)
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

#[derive(Debug, Deserialize)]
struct MumpConfig {
    users: Vec<UserSpec>,
}

#[derive(Debug, Deserialize)]
struct UserSpec {
    id: String,
    sources: Vec<SourceSpec>,
}

#[derive(Debug, Deserialize)]
struct SourceSpec {
    func: String,
    local: u32,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

struct PtsEdge {
    src: String,
    dst: String,
}

struct Parsed {
    name_to_id: HashMap<String, u32>,
    id_to_name: HashMap<u32, String>,
    edges: Vec<PtsEdge>,
    num_pointer_entries: usize,
}

fn parse_pts(contents: &str) -> Parsed {
    let mut name_to_id = HashMap::new();
    let mut id_to_name = HashMap::new();
    let mut edges = Vec::new();
    let mut num_pointer_entries = 0usize;

    for line in contents.lines() {
        // header: FuncId(N) - "name"
        if line.starts_with("FuncId(") && line.contains(") - \"") {
            if let (Some(open), Some(close)) = (line.find('('), line.find(')')) {
                if let Ok(id) = line[open + 1..close].parse::<u32>() {
                    if let (Some(fq), Some(lq)) = (line.find('"'), line.rfind('"')) {
                        if lq > fq {
                            let name = line[fq + 1..lq].to_string();
                            name_to_id.insert(name.clone(), id);
                            id_to_name.insert(id, name);
                        }
                    }
                }
            }
            continue;
        }
        // entry: \t<src> (<count>) ==> { <dst1> <dst2> ... }
        if line.starts_with('\t') {
            let trimmed = line.trim_start();
            let Some(arrow) = trimmed.find("==>") else {
                continue;
            };
            let lhs = trimmed[..arrow].trim();
            let rhs = trimmed[arrow + 3..].trim();

            let src = if let Some(paren) = lhs.rfind(" (") {
                lhs[..paren].trim().to_string()
            } else {
                lhs.to_string()
            };
            let rhs = rhs.trim_start_matches('{').trim_end_matches('}').trim();

            num_pointer_entries += 1;
            for dst in rhs.split_whitespace() {
                edges.push(PtsEdge {
                    src: src.clone(),
                    dst: dst.to_string(),
                });
            }
        }
    }

    Parsed {
        name_to_id,
        id_to_name,
        edges,
        num_pointer_entries,
    }
}

/// `path` is a prefix-extension of `prefix` iff `path == prefix` or
/// `path` starts with `prefix` followed by a projection marker ('.').
/// This is the rule used to decide whether a pts entry keyed at `path`
/// should be treated as a seed (when `prefix` is a seed).
fn is_prefix_extension(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if path.len() > prefix.len() && path.as_bytes()[..prefix.len()] == *prefix.as_bytes() {
        let rest = &path[prefix.len()..];
        return rest.starts_with('.');
    }
    false
}

fn annotate(path: &str, id_to_name: &HashMap<u32, String>) -> String {
    if let Some(start) = path.find("FuncId(") {
        let after = &path[start + "FuncId(".len()..];
        if let Some(close) = after.find(')') {
            if let Ok(id) = after[..close].parse::<u32>() {
                if let Some(name) = id_to_name.get(&id) {
                    return format!(" // {}", name);
                }
            }
        }
    }
    String::new()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let started = Instant::now();

    let pts_content = fs::read_to_string(&args.pts)?;
    let config: MumpConfig = serde_json::from_str(&fs::read_to_string(&args.config)?)?;

    let parse_started = Instant::now();
    let parsed = parse_pts(&pts_content);
    let parse_time = parse_started.elapsed();

    // Materialize user seed prefixes
    let mut user_taint: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut user_seeds: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for user in &config.users {
        let mut seeds = BTreeSet::new();
        let mut seed_list = Vec::new();
        for src in &user.sources {
            let Some(&fid) = parsed.name_to_id.get(&src.func) else {
                eprintln!(
                    "warning: function '{}' not found in pts dump; skipping seed local_{}",
                    src.func, src.local
                );
                continue;
            };
            let seed = format!("FuncId({})::local_{}", fid, src.local);
            seed_list.push(seed.clone());
            seeds.insert(seed);
        }
        user_taint.insert(user.id.clone(), seeds);
        user_seeds.insert(user.id.clone(), seed_list);
    }

    // Fixpoint over the pts edge set.
    // A user u reaches object dst if some edge src==>dst has src prefix-matching
    // a node already reached by u.  Seeds bootstrap the reached set.
    let fixpoint_started = Instant::now();
    let mut iterations = 0u32;
    loop {
        iterations += 1;
        let mut changed = false;
        for (_user, tainted) in user_taint.iter_mut() {
            let snapshot: Vec<String> = tainted.iter().cloned().collect();
            for edge in &parsed.edges {
                let src_tainted = snapshot.iter().any(|t| is_prefix_extension(&edge.src, t));
                if src_tainted && tainted.insert(edge.dst.clone()) {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let fixpoint_time = fixpoint_started.elapsed();

    // Compute cross-user overlap
    let mut per_object: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (user, tainted) in &user_taint {
        for node in tainted {
            per_object.entry(node.clone()).or_default().insert(user.clone());
        }
    }
    let overlap: BTreeMap<String, BTreeSet<String>> = per_object
        .into_iter()
        .filter(|(_, users)| users.len() >= 2)
        .collect();

    // Prune: drop projection-extensions of entries that share the same user set
    // (they are trivially implied and make the report noisy for the paper).
    let overlap_keys: Vec<String> = overlap.keys().cloned().collect();
    let mut pruned: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for key in &overlap_keys {
        let users = &overlap[key];
        let redundant = overlap_keys.iter().any(|other| {
            other != key
                && other.len() < key.len()
                && is_prefix_extension(key, other)
                && &overlap[other] == users
        });
        if !redundant {
            pruned.insert(key.clone(), users.clone());
        }
    }

    let total_time = started.elapsed();

    // Report
    println!("================ AFG MUMP Overlap Report ================");
    println!(
        "Input:  pts={} functions={} pointer-entries={} edges={}",
        args.pts.display(),
        parsed.id_to_name.len(),
        parsed.num_pointer_entries,
        parsed.edges.len()
    );
    println!();

    println!("Seeds (MUMP user origin tags):");
    for (uid, seeds) in &user_seeds {
        println!("  [{}]", uid);
        for s in seeds {
            let ann = annotate(s, &parsed.id_to_name);
            println!("    seed: {}{}", s, ann);
        }
    }
    println!();

    println!("Per-user reachable abstract-object counts:");
    for (uid, tainted) in &user_taint {
        println!("  {}: {}", uid, tainted.len());
    }
    println!();

    println!("Timing:");
    println!("  pts parse:        {:.3?}", parse_time);
    println!("  taint fixpoint:   {:.3?} ({} iterations)", fixpoint_time, iterations);
    println!("  total post-pass:  {:.3?}", total_time);
    println!();

    println!(
        "Cross-user overlap: {} raw nodes, {} representative after prefix-dedup.",
        overlap.len(),
        pruned.len()
    );
    println!();
    println!("Representative overlap nodes (STPA-flagged pointers/objects):");
    for (node, users) in &pruned {
        let users_list: Vec<String> = users.iter().cloned().collect();
        let ann = annotate(node, &parsed.id_to_name);
        println!("  {}  [reached by: {}]{}", node, users_list.join(", "), ann);
    }
    println!();
    println!("================ end ================");

    if args.verbose {
        for (uid, tainted) in &user_taint {
            println!("\n[verbose] {} reachable objects ({}):", uid, tainted.len());
            for n in tainted {
                println!("  {}", n);
            }
        }
    }

    Ok(())
}
