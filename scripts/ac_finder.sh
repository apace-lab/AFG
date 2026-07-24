#!/usr/bin/env bash
# One-stop wrapper around the AC-finder binaries (find_ac_points*).
# Pick a single scanner or run all of them together via the "all" mode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ac_finder.sh <mode> [args...]

Modes (pick exactly one):
  mir       Scan a RUPTA MIR dump               -> find_ac_points
  rs-src    Scan Rust source directly            -> find_ac_points_src
  js        Scan JS/TS source                    -> find_ac_points_js
  llvm      Scan a real LLVM IR module (.ll/.bc) -> find_ac_points_llvm
  all       Run any combination of the above in one pass -> find_ac_points_all

Everything after <mode> is forwarded as-is to that binary's own CLI, so
run `ac_finder.sh <mode> --help` to see its exact flags.

Examples:
  ac_finder.sh mir    --mir examples/demo_mir.txt
  ac_finder.sh rs-src --src src/
  ac_finder.sh js     --src frontend/src
  ac_finder.sh llvm   --ir examples/ac_demo_llvm.ll
  ac_finder.sh all    --mir dump.txt --rs-src src/ --src frontend/src

Notes:
  - "llvm" mode, and "all" whenever --llvm-ir is passed, need LLVM installed
    (llvm-config on PATH) and are built with --features llvm-ir-scan; see
    src/AC_FINDER.md#scanning-real-llvm-ir.
  - Runs "cargo run --release" under the hood, from the repo root, so it
    works regardless of your current directory.
EOF
}

if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

mode="$1"
shift

cd "$REPO_ROOT"

case "$mode" in
  mir)
    exec cargo run --release --bin find_ac_points -- "$@"
    ;;
  rs-src)
    exec cargo run --release --bin find_ac_points_src -- "$@"
    ;;
  js)
    exec cargo run --release --bin find_ac_points_js -- "$@"
    ;;
  llvm)
    exec cargo run --release --features llvm-ir-scan --bin find_ac_points_llvm -- "$@"
    ;;
  all)
    features=()
    for arg in "$@"; do
      case "$arg" in
        --llvm-ir|--llvm-ir=*)
          features=(--features llvm-ir-scan)
          break
          ;;
      esac
    done
    exec cargo run --release "${features[@]}" --bin find_ac_points_all -- "$@"
    ;;
  *)
    echo "Unknown mode: $mode" >&2
    echo >&2
    usage >&2
    exit 1
    ;;
esac
