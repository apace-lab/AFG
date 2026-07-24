#!/usr/bin/env bash
# One-stop wrapper around the LLM-API-finder binaries (find_llm_calls*).
# Pick a single scanner or run both of them together via the "all" mode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: llm_api_finder.sh <mode> [args...]

Modes (pick exactly one):
  mir    Scan a RUPTA MIR dump    -> find_llm_calls
  js     Scan JS/TS source        -> find_llm_calls_js
  all    Run both of the above in one pass -> find_llm_calls_all

Everything after <mode> is forwarded as-is to that binary's own CLI, so
run `llm_api_finder.sh <mode> --help` to see its exact flags.

Examples:
  llm_api_finder.sh mir --mir examples/demo_mir.txt
  llm_api_finder.sh js  --src frontend/src
  llm_api_finder.sh all --mir examples/demo_mir.txt --src frontend/src

Notes:
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
    exec cargo run --release --bin find_llm_calls -- "$@"
    ;;
  js)
    exec cargo run --release --bin find_llm_calls_js -- "$@"
    ;;
  all)
    exec cargo run --release --bin find_llm_calls_all -- "$@"
    ;;
  *)
    echo "Unknown mode: $mode" >&2
    echo >&2
    usage >&2
    exit 1
    ;;
esac
