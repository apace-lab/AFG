# AFG

[![CI](https://github.com/apace-lab/AFG/actions/workflows/ci.yml/badge.svg)](https://github.com/apace-lab/AFG/actions/workflows/ci.yml)

Access Flow Guard (AFG) is a framework for detecting cross-user data leaks in
multi-user Rust programs, in particular LLM-powered applications that share
caches, databases, or other global state across user sessions.


## What it does

AFG is structured in four stages. This repository currently implements the
first two.

Stage 1, MUMP (Multi-User, Multi-Permission), tags each user's input with a
distinct origin marker. The mapping from user identity to MIR source is given
in a JSON config.

Stage 2, STPA (Scoped Taint Pointer Analysis), propagates origin tags through
the pointer assignment graph to a fixed point and reports every abstract
object reached by two or more distinct users. These are the cross-user
overlap sites.



## Build

```sh
cargo build --release
```

Stable Rust. Dependencies: `serde`, `serde_json`, `clap`, `regex`, `walkdir`.
Produces eight binaries in `target/release/`, plus a ninth
(`find_ac_points_llvm`) if you opt into the `llvm-ir-scan` feature — see its
entry below:

- `afg` — the MUMP/STPA overlap detector (this section).
- `find_llm_calls` — scans a RUPTA MIR dump for LLM API call sites. See
  [`src/LLM_API_FINDER.md`](src/LLM_API_FINDER.md).
- `find_llm_calls_js` — scans JS/TS source for LLM API call sites. See
  [`src/LLM_API_FINDER_JS.md`](src/LLM_API_FINDER_JS.md).
- `find_llm_calls_all` — runs both of the above and merges the output. See
  [Running both scans
  together](src/LLM_API_FINDER_JS.md#running-both-scans-together-find_llm_calls_all).
- `find_ac_points` — scans a RUPTA MIR dump for access-control (authn/authz)
  call sites. See [`src/AC_FINDER.md`](src/AC_FINDER.md).
- `find_ac_points_src` — scans Rust source directly for access-control call
  sites, no MIR dump required. See [`src/AC_FINDER.md`](src/AC_FINDER.md).
- `find_ac_points_js` — scans JS/TS source for access-control call sites. See
  [`src/AC_FINDER_JS.md`](src/AC_FINDER_JS.md).
- `find_ac_points_all` — runs `find_ac_points`, `find_ac_points_src`,
  `find_ac_points_js`, and (with `--features llvm-ir-scan`)
  `find_ac_points_llvm`, merging the output.
- `find_ac_points_llvm` — scans a real LLVM IR module (`.ll`/`.bc`) for
  access-control call sites, using the [`llvm-ir`](https://github.com/cdisselkoen/llvm-ir)
  crate. Opt-in only — `cargo build --release --features llvm-ir-scan` — since
  it needs a real LLVM installation at build time, unlike every other binary
  here. See [`src/AC_FINDER.md`](src/AC_FINDER.md#scanning-real-llvm-ir).

### Convenience wrapper: `scripts/ac_finder.sh`

[`scripts/ac_finder.sh`](scripts/ac_finder.sh) is a single dispatcher over the
five `find_ac_points*` binaries above, so you don't have to remember which
binary name goes with which target — pick a mode and it runs `cargo run
--release` for you:

```sh
scripts/ac_finder.sh mir    --mir examples/demo_mir.txt      # find_ac_points
scripts/ac_finder.sh rs-src --src src/                        # find_ac_points_src
scripts/ac_finder.sh js     --src frontend/src                # find_ac_points_js
scripts/ac_finder.sh llvm   --ir examples/ac_demo_llvm.ll     # find_ac_points_llvm
scripts/ac_finder.sh all    --mir dump.txt --rs-src src/ --src frontend/src  # find_ac_points_all
```

Everything after `<mode>` is forwarded verbatim to that binary's own `clap`
CLI, so every flag documented above (`--out`, `--datasets`,
`--all-http-calls`, `--include-node-modules`, `--include-target-dir`, ...)
works unchanged, and `scripts/ac_finder.sh <mode> --help` prints that
binary's real `--help`. `llvm` mode, and `all` whenever `--llvm-ir` is
passed, automatically add `--features llvm-ir-scan` — still requires LLVM
installed as described above. Run `scripts/ac_finder.sh` with no arguments
for the full usage text.

### Convenience wrapper: `scripts/llm_api_finder.sh`

[`scripts/llm_api_finder.sh`](scripts/llm_api_finder.sh) is the same kind of
dispatcher, over the three `find_llm_calls*` binaries:

```sh
scripts/llm_api_finder.sh mir --mir examples/demo_mir.txt              # find_llm_calls
scripts/llm_api_finder.sh js  --src frontend/src                        # find_llm_calls_js
scripts/llm_api_finder.sh all --mir examples/demo_mir.txt --src frontend/src  # find_llm_calls_all
```

Same rules as `ac_finder.sh`: everything after `<mode>` is forwarded verbatim
to that binary's own `clap` CLI (`--out`, `--datasets`, `--all-http-calls`,
`--include-node-modules`, ...), and `scripts/llm_api_finder.sh <mode> --help`
prints that binary's real `--help`. No LLVM feature here — the LLM finder has
no LLVM-IR scanner. Run `scripts/llm_api_finder.sh` with no arguments for the
full usage text.

## Usage

```sh
afg --pts <pts_dump> --config <mump_config.json> [--verbose]
```

Arguments:

- `--pts`: Path to the points-to dump produced by
  `cargo pta -- --dump-pts <path>`.
- `--config`: Path to a MUMP user config (schema below).
- `--verbose`: Print each user's full reachable set after the fixed point.
  Off by default.

## End-to-end example

The `examples/` directory contains a pre-generated points-to dump from the
AFG demo program and a matching user config. The demo simulates two users
querying an LLM-style cache backed by a shared `Arc<Mutex<HashMap<String,
String>>>`, which is the running example in the AFG paper.

Run directly on the included sample:

```sh
cargo build --release
./target/release/afg \
    --pts examples/demo_pts.sample.txt \
    --config examples/mump_config.json
```

Expected output (three overlap nodes, which are the expected leak sites):

```
Representative overlap nodes (STPA-flagged pointers/objects):
  FuncId(11)::heap_bb0[2].cast#2  [reached by: UserA, UserB] // alloc::boxed::{impl#0}::new<alloc::sync::ArcInner<std::sync::Mutex<std::collections::HashMap<...>>>>
  FuncId(215)::heap_bb0[1]        [reached by: UserA, UserB] // hashbrown::raw::alloc::inner::do_alloc<std::alloc::Global>
  FuncId(51)::heap_bb0[5]         [reached by: UserA, UserB] // alloc::str::{impl#4}::to_owned
```

Interpretation: the shared `Arc<Mutex<HashMap>>` allocation, the HashMap's
hashbrown backing storage, and the cached answer `String` are all reachable
from both users. These are true positives matching the paper's description
of the leak.

### Regenerating the dump from source

Install [RUPTA](https://github.com/rustanlys/rupta) first. The bundled
`demo/` directory is the reference Rust program the sample dump was derived
from. It pins RUPTA's nightly via its own `rust-toolchain.toml`.

```sh
cd demo
cargo pta -- \
    --entry-func main \
    --dump-pts /tmp/demo_pts.txt \
    --dump-call-graph /tmp/demo_cg.dot
cd ..
./target/release/afg --pts /tmp/demo_pts.txt --config examples/mump_config.json
```

## Config schema

`mump_config.json`:

```json
{
  "users": [
    {
      "id": "UserA",
      "sources": [
        { "func": "demo::main", "local": 5,  "note": "Arc clone for UserA" },
        { "func": "demo::main", "local": 7,  "note": "UserA's question string" },
        { "func": "demo::main", "local": 8,  "note": "\"UserA\" literal" }
      ]
    },
    {
      "id": "UserB",
      "sources": [
        { "func": "demo::main", "local": 10, "note": "Arc clone for UserB" },
        { "func": "demo::main", "local": 12, "note": "UserB's question string" },
        { "func": "demo::main", "local": 13, "note": "\"UserB\" literal" }
      ]
    }
  ]
}
```

Fields:

- `users[].id`: Arbitrary user label. Used as the origin tag in the report.
- `users[].sources[].func`: Demangled Rust function name exactly as it appears
  in the points-to dump (e.g., `demo::main`,
  `async_openai::chat::Chat::create`). Matching is exact.
- `users[].sources[].local`: MIR local index inside that function. Integer.
  Maps to `FuncId(N)::local_M` in RUPTA's dump.
- `users[].sources[].note`: Optional human-readable comment. Ignored by the
  tool.

To find the right MIR locals for a program:

- Inspect the MIR dump (`cargo pta -- --dump-mir <path>`) and read the local
  assignments in the function you care about, or
- Run `afg --verbose` and cross-check the reachable set against the pts dump.

## Output

`afg` prints:

1. A header with input sizes: number of functions, pointer entries, and edges
   parsed from the pts dump.
2. The seeds as resolved from the config, annotated with the function name.
3. Per-user reachable object counts.
4. Timing: parse time, fixed-point time, and total post-pass time.
5. The cross-user overlap set, pruned to one representative per projection
   chain. Each entry is annotated with the Rust function the abstract
   allocation originated in, for example `alloc::sync::ArcInner<...>`.

Each entry in the overlap set has the form:

```
FuncId(N)::<path>  [reached by: UserA, UserB, ...]  // <demangled origin>
```

where:

- `FuncId(N)` identifies a monomorphized function in RUPTA's index.
- `heap_bb0[K]` is a heap allocation in that function at block 0, statement
  K.
- `.cast#K`, `.N`, and `.index.K` are projections onto casts, struct fields,
  and array indices. The prefix pruning shows the topmost tainted path for
  each leak rather than every projection under it.
- `[reached by: ...]` lists the user origin tags that propagated to this
  object. Any object with two or more tags is a cross-user overlap.

## Algorithm

Let the points-to relation be a set of edges `E`. Each edge is a pair
`(src, dst)` of path strings from the pts dump.

Define the prefix-extension relation: path `p` extends prefix `q` iff
`p == q` or `p` starts with `q.`. This captures MIR projections, so tagging
a local `x` automatically tags `x.0`, `x.0.1`, and so on.

For each user `u`, let `S_u` be the set of seed paths from the config.

Compute the reachable set `R_u`:

1. Initialize `R_u := S_u`.
2. Repeat: for every edge `(src, dst)` in `E`, if `src` extends any element
   of `R_u`, insert `dst` into `R_u`.
3. Stop when `R_u` has no changes in an iteration.

The cross-user overlap is:

```
O = { o | #{ u : o in R_u } >= 2 }
```

The report prunes `O` by dropping entries that are projection-extensions of
another entry in `O` with the same user set. This keeps the output readable
without losing information, because any projection of an overlap object is
also an overlap object with the same tag set.

Complexity per iteration is `O(|Users| * |E| * |R_u|)` in the worst case.
For the AFG demo (1055 edges, 2 users, 6-object reachable sets), the full
fixed point runs in under 100 microseconds.


### Notes on the `datasets/` directory

This directory holds curated signature catalogues, grouped by source project
or SDK. Some are reference data for a future MUMP feature; others are already
consumed at runtime by the `find_llm_calls*`/`find_ac_points*` binaries (noted
per-entry below). The main `afg` tool (MUMP/STPA) does not read any of them.

- `rust_input_functions.json`: user-input entry functions surveyed from
  popular open-source Rust LPAs. Reference data for a future MUMP feature
  that auto-generates `mump_config.json` seeds by matching function
  signatures in a target program against these catalogues — not yet consumed
  by any tool in this repository.
- `JsTs_input_functions.json`, `otherlang_input_functions.json`: equivalents
  for JavaScript/TypeScript and other non-Rust languages. Also not yet
  consumed.
- `llm_api_functions.json`: LLM SDK call signatures (async-openai,
  ollama-rs, gemini-rust, anthropic-sdk, clust, misanthropic, rig-core,
  genai, etc.). Each entry is annotated with a `verified_via` tag indicating
  whether the signature was confirmed against upstream crate docs or is
  still pending verification. Consumed by
  [`find_llm_calls`](src/LLM_API_FINDER.md), which scans a RUPTA MIR dump for
  matching call sites.
- `llm_api_functions_js.json`: the JS/TS equivalent, consumed by
  [`find_llm_calls_js`](src/LLM_API_FINDER_JS.md), which scans JS/TS source
  text directly (no MIR/RUPTA step — RUPTA doesn't understand JS) for LLM SDK
  and raw `fetch`/`axios` call sites. This covers the frontend half of
  Tauri-style apps where `find_llm_calls` alone would report nothing, because
  the LLM calls never appear in the compiled Rust binary at all.
  `find_llm_calls_all` runs `find_llm_calls` and `find_llm_calls_js` together
  in one pass and merges the output — see [Running both scans
  together](src/LLM_API_FINDER_JS.md#running-both-scans-together-find_llm_calls_all).
- `ac_functions.json`: access-control (authn/authz) call signatures —
  actix-web-httpauth, jsonwebtoken, casbin-rs, oso, biscuit-auth, etc.
  Consumed by [`find_ac_points`](src/AC_FINDER.md), which scans a RUPTA MIR
  dump; by `find_ac_points_src`, which scans Rust source directly (no
  MIR/RUPTA step needed) for the same call sites; and by
  `find_ac_points_llvm` (opt-in, `--features llvm-ir-scan`), which scans a
  real LLVM IR module, matching demangled call targets against the same
  catalogue.
- `ac_functions_js.json`: the JS/TS equivalent, consumed by
  [`find_ac_points_js`](src/AC_FINDER_JS.md), which scans JS/TS source text
  directly for access-control middleware, guards, and raw HTTP authz calls.
  `find_ac_points_all` runs all of `find_ac_points`, `find_ac_points_src`,
  `find_ac_points_js`, and (with `--features llvm-ir-scan`)
  `find_ac_points_llvm` in one pass and merges the output.

## Testing

```sh
cargo test --release                          # everything except find_ac_points_llvm
cargo test --release --features llvm-ir-scan  # also exercises find_ac_points_llvm
```

[`tests/fixtures.rs`](tests/fixtures.rs) runs each `find_ac_points*` binary
against the worked-example fixtures referenced throughout the docs above
(`examples/ac_demo_mir.txt`, `examples/src/ac_demo.rs`,
`examples/src/ac_demo_js.ts`, `examples/ac_demo_llvm.ll`) and asserts on the
resulting JSON, so a change that breaks a documented example fails
`cargo test` instead of silently drifting from what's written down.
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs both commands
above on every push and pull request against `main`.

## License

Dual licensed under MIT or Apache-2.0 per the bundled `LICENSE` file.
