#!/usr/bin/env bash
# Point this at any repo -- a GitHub URL or a local path -- and it runs the
# AC finder (find_ac_points_all: Rust source + JS/TS source) over the whole
# thing and writes one merged JSON report. This is the "any repo like this"
# generalization of the ac_matches_bionic.json / ac_matches_hub.json workflow.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scan_repo.sh <git-url-or-local-path> [options] [-- extra-args...]

Clones (or reuses) the target under repos/<name>/ if given a URL, or scans a
local path directly, then runs find_ac_points_all over it and writes a
merged JSON report.

By default this only runs the two purely-syntactic scanners -- Rust source
(--rs-src) and JS/TS source (--src). It does NOT build the target or produce
a RUPTA MIR dump or an LLVM IR module, so the Rust-MIR and real-LLVM-IR
scanners (--mir / --llvm-ir) are skipped even though they're strictly more
precise on generic/trait-dispatch call sites (they see the real
monomorphized callee, not just source text) -- see src/AC_FINDER.md. If you
already have a MIR dump or an .ll/.bc module for the target (produced
separately -- this script doesn't generate them), pass --mir-dump/--llvm-ir
below to fold them into the same merged report.

Options:
  --name <short-name>   Name used for repos/<name> and the output file
                         (default: derived from the URL/path basename)
  --out-dir <dir>       Directory to write ac_matches_<name>.json into
                         (default: repo root)
  --pull                If already cloned, git pull before scanning
  --mir-dump <path>     Also fold in a pre-generated RUPTA MIR dump (.txt)
                         for this target -- forwarded as find_ac_points_all's
                         --mir
  --llvm-ir <path>      Also fold in a pre-generated LLVM IR module (.ll or
                         .bc) for this target -- requires find_ac_points_all
                         to have been built with --features llvm-ir-scan
  -h, --help            Show this help

Anything after a literal `--` is forwarded as-is to find_ac_points_all, e.g.
`--all-http-calls`, `--include-node-modules`, `--include-target-dir`.

Examples:
  scripts/scan_repo.sh https://github.com/traceloop/hub
  scripts/scan_repo.sh https://github.com/bionic-gpt/bionic-gpt --pull
  scripts/scan_repo.sh ../some-local-checkout --name local-app
  scripts/scan_repo.sh https://github.com/foo/bar -- --all-http-calls
  scripts/scan_repo.sh ../local-checkout --mir-dump ../local-checkout.mir.txt

Notes:
  - Clones go to repos/ (gitignored) with `git clone --depth 1`, so history
    isn't fetched -- fine for scanning, not for further git work in there.
  - Runs "cargo run --release" under the hood, from the repo root, so it
    works regardless of your current directory.
EOF
}

if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

target="$1"
shift

name=""
out_dir=""
do_pull=0
mir_dump=""
llvm_ir=""
extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      name="$2"
      shift 2
      ;;
    --out-dir)
      out_dir="$2"
      shift 2
      ;;
    --pull)
      do_pull=1
      shift
      ;;
    --mir-dump)
      mir_dump="$2"
      shift 2
      ;;
    --llvm-ir)
      llvm_ir="$2"
      shift 2
      ;;
    --)
      shift
      extra_args=("$@")
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
done

cd "$REPO_ROOT"

# Derive a default --name from the URL/path: strip trailing slash and .git,
# take the last path segment, sanitize to [A-Za-z0-9_-].
derive_name() {
  local raw="${1%/}"
  raw="${raw%.git}"
  raw="${raw##*/}"
  raw="${raw//[^A-Za-z0-9_-]/-}"
  echo "$raw"
}

is_url=0
case "$target" in
  http://*|https://*|git@*|ssh://*)
    is_url=1
    ;;
esac

if [[ -z "$name" ]]; then
  name="$(derive_name "$target")"
fi
if [[ -z "$name" ]]; then
  echo "Could not derive a --name from '$target'; pass one explicitly." >&2
  exit 1
fi

if [[ "$is_url" -eq 1 ]]; then
  clone_dir="$REPO_ROOT/repos/$name"
  if [[ -d "$clone_dir/.git" ]]; then
    if [[ "$do_pull" -eq 1 ]]; then
      echo "[scan_repo] $clone_dir already exists -- pulling latest" >&2
      git -C "$clone_dir" pull --ff-only
    else
      echo "[scan_repo] $clone_dir already exists -- reusing as-is (pass --pull to refresh)" >&2
    fi
  else
    echo "[scan_repo] cloning $target -> $clone_dir" >&2
    mkdir -p "$REPO_ROOT/repos"
    git clone --depth 1 "$target" "$clone_dir"
  fi
  scan_path="$clone_dir"
else
  if [[ ! -d "$target" ]]; then
    echo "Local path not found: $target" >&2
    exit 1
  fi
  scan_path="$(cd "$target" && pwd)"
fi

if [[ -n "$mir_dump" && ! -f "$mir_dump" ]]; then
  echo "MIR dump not found: $mir_dump" >&2
  exit 1
fi
if [[ -n "$llvm_ir" && ! -f "$llvm_ir" ]]; then
  echo "LLVM IR module not found: $llvm_ir" >&2
  exit 1
fi

if [[ -z "$out_dir" ]]; then
  out_dir="$REPO_ROOT"
fi
mkdir -p "$out_dir"
out_file="$out_dir/ac_matches_$name.json"

extra_scan_args=()
cargo_features=()
if [[ -n "$mir_dump" ]]; then
  extra_scan_args+=(--mir "$mir_dump")
fi
if [[ -n "$llvm_ir" ]]; then
  extra_scan_args+=(--llvm-ir "$llvm_ir")
  # --llvm-ir is a hard error at runtime unless find_ac_points_all was built
  # with this feature -- see src/AC_FINDER.md#scanning-real-llvm-ir for the
  # LLVM installation it requires.
  cargo_features+=(--features llvm-ir-scan)
fi

echo "[scan_repo] scanning $scan_path" >&2
exec cargo run --release --bin find_ac_points_all "${cargo_features[@]}" -- \
  --rs-src "$scan_path" \
  --src "$scan_path" \
  --out "$out_file" \
  "${extra_scan_args[@]}" \
  "${extra_args[@]}"
