# AFG

[![CI](https://github.com/apace-lab/AFG/actions/workflows/ci.yml/badge.svg)](https://github.com/apace-lab/AFG/actions/workflows/ci.yml)

Access Flow Guard (AFG) detects cross-user data leaks in multi-user Rust
programs — in particular LLM-powered apps that share caches, databases, or
other global state across user sessions.

It also ships a family of standalone scanners that find every LLM API call
and every access-control (auth) check in a codebase, Rust or JS/TS, with or
without a full program analysis.

## What's in this repo

| Binary | Scans | Docs |
|---|---|---|
| `afg` | A RUPTA points-to dump, for cross-user overlap (the main tool — see below) | this file |
| `find_llm_calls` | Rust MIR dump, for LLM API calls | [LLM_API_FINDER.md](src/LLM_API_FINDER.md) |
| `find_llm_calls_js` | JS/TS source, for LLM API calls | [LLM_API_FINDER_JS.md](src/LLM_API_FINDER_JS.md) |
| `find_llm_calls_all` | Both of the above, merged | [LLM_API_FINDER_JS.md](src/LLM_API_FINDER_JS.md#running-both-scans-together-find_llm_calls_all) |
| `find_ac_points` | Rust MIR dump, for access-control calls | [AC_FINDER.md](src/AC_FINDER.md) |
| `find_ac_points_src` | Rust source directly, for access-control calls | [AC_FINDER.md](src/AC_FINDER.md) |
| `find_ac_points_js` | JS/TS source, for access-control calls | [AC_FINDER_JS.md](src/AC_FINDER_JS.md) |
| `find_ac_points_all` | Any combination of the three above, merged | [AC_FINDER.md](src/AC_FINDER.md) |
| `find_ac_points_llvm` | Real LLVM IR (`.ll`/`.bc`), for access-control calls — opt-in, needs LLVM installed | [AC_FINDER.md](src/AC_FINDER.md#scanning-real-llvm-ir) |

## Build

```sh
cargo build --release
```

Stable Rust. Produces every binary above except `find_ac_points_llvm`, which
needs a separate opt-in build (see its doc link above):

```sh
cargo build --release --features llvm-ir-scan
```

### Convenience wrappers

Three scripts save you from remembering which binary goes with which target:

```sh
scripts/ac_finder.sh mir --mir dump.txt          # -> find_ac_points
scripts/ac_finder.sh rs-src --src src/           # -> find_ac_points_src
scripts/ac_finder.sh js --src frontend/src       # -> find_ac_points_js
scripts/ac_finder.sh llvm --ir module.ll         # -> find_ac_points_llvm
scripts/ac_finder.sh all --mir dump.txt --src frontend/src  # -> find_ac_points_all

scripts/llm_api_finder.sh mir --mir dump.txt     # -> find_llm_calls
scripts/llm_api_finder.sh js --src frontend/src  # -> find_llm_calls_js
scripts/llm_api_finder.sh all --mir dump.txt --src frontend/src  # -> find_llm_calls_all

scripts/scan_repo.sh https://github.com/some/repo   # clones + runs find_ac_points_all over it
```

Everything after the mode/target is forwarded to the underlying binary's own
`--help`-documented flags. Run any script with no arguments for full usage.

## Running `afg` (the overlap detector)

```sh
afg --pts <pts_dump> --config <mump_config.json> [--verbose]
```

- `--pts` — points-to dump from `cargo pta -- --dump-pts <path>` (via [RUPTA](https://github.com/rustanlys/rupta))
- `--config` — a MUMP user config (schema below)
- `--verbose` — print each user's full reachable set

### Try it on the bundled demo

```sh
cargo build --release
./target/release/afg --pts examples/demo_pts.sample.txt --config examples/mump_config.json
```

Expected output — three overlap nodes, the leak sites in the AFG paper's demo
(two users sharing an `Arc<Mutex<HashMap>>` LLM-response cache):

```
Representative overlap nodes (STPA-flagged pointers/objects):
  FuncId(11)::heap_bb0[2].cast#2  [reached by: UserA, UserB] // alloc::boxed::{impl#0}::new<alloc::sync::ArcInner<std::sync::Mutex<std::collections::HashMap<...>>>>
  FuncId(215)::heap_bb0[1]        [reached by: UserA, UserB] // hashbrown::raw::alloc::inner::do_alloc<std::alloc::Global>
  FuncId(51)::heap_bb0[5]         [reached by: UserA, UserB] // alloc::str::{impl#4}::to_owned
```

Each line names an abstract allocation reached by more than one user's
tainted data — the cache `Arc`/`Mutex`, its `HashMap` backing storage, and
the cached answer string.

### Regenerating the dump from your own program

```sh
cd demo   # bundled reference program, pins RUPTA's nightly via rust-toolchain.toml
cargo pta -- --entry-func main --dump-pts /tmp/my_pts.txt
cd ..
./target/release/afg --pts /tmp/my_pts.txt --config examples/mump_config.json
```

### Config schema

```json
{
  "users": [
    {
      "id": "UserA",
      "sources": [
        { "func": "demo::main", "local": 5, "note": "Arc clone for UserA" },
        { "func": "demo::main", "local": 7, "note": "UserA's question string" }
      ]
    }
  ]
}
```

- `users[].id` — arbitrary label, used as the origin tag in the report
- `users[].sources[].func` — demangled Rust function name exactly as it
  appears in the points-to dump (e.g. `demo::main`)
- `users[].sources[].local` — MIR local index inside that function (integer);
  find these with `cargo pta -- --dump-mir <path>` or `afg --verbose`
- `users[].sources[].note` — optional, ignored by the tool

### Reading the output

`afg` prints input sizes, the resolved seeds, per-user reachable counts,
timing, and the cross-user overlap set (pruned to one representative per
projection chain). Each overlap entry looks like:

```
FuncId(N)::<path>  [reached by: UserA, UserB, ...]  // <demangled origin>
```

`FuncId(N)` is a monomorphized function in RUPTA's index; `heap_bb0[K]` is a
heap allocation at block 0, statement K; `.cast#K`/`.N`/`.index.K` are
projections (casts, struct fields, array indices). Any object reached by two
or more user tags is a cross-user overlap — a candidate leak.

<details>
<summary>How the overlap computation works</summary>

For each user `u`, seed the reachable set `R_u` with their config sources,
then repeatedly follow points-to edges `(src, dst)` — if `src` extends
(equals, or is a prefix of) anything already in `R_u`, add `dst`. Iterate to
a fixed point. The overlap set is every object reachable by two or more
users' `R_u`. Runs in well under a millisecond on the bundled demo (1055
edges, 2 users).
</details>

## The `datasets/` directory

Curated signature catalogues consumed by the finder tools:

| File | Consumed by |
|---|---|
| `llm_api_functions.json` | `find_llm_calls` |
| `llm_api_functions_js.json` | `find_llm_calls_js` |
| `ac_functions.json` | `find_ac_points`, `find_ac_points_src`, `find_ac_points_llvm` |
| `ac_functions_js.json` | `find_ac_points_js` |
| `rust_input_functions.json`, `JsTs_input_functions.json`, `otherlang_input_functions.json` | not yet consumed — reference data for a future MUMP auto-config feature |

Add a new library to any of the first four by editing its JSON file — no
rebuild needed. See each tool's own doc for the entry format.

## Testing

```sh
cargo test --release                          # everything except find_ac_points_llvm
cargo test --release --features llvm-ir-scan  # also exercises find_ac_points_llvm
```

[`tests/fixtures.rs`](tests/fixtures.rs) runs each binary against the worked
examples in `examples/` and checks the JSON output, so a change that breaks
a documented example fails `cargo test`. CI runs both commands above on
every push/PR against `main`.

## License

Dual licensed under MIT or Apache-2.0 — see [`LICENSE`](LICENSE).
