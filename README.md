# AFG

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

Stable Rust. Dependencies: `serde`, `serde_json`, `clap`. The release binary
is produced at `target/release/afg`.

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

These JSON files are curated signature catalogues of entry-point functions
that carry user input, grouped by source project or SDK. They are reference
data for a future MUMP feature that auto-generates `mump_config.json` seeds
by matching function signatures in a target program against these catalogues.
The current `afg` tool does not read them; they are included so the
framework's data and implementation stay in one repository.

- `rust_input_functions.json`: user-input entry functions surveyed from
  popular open-source Rust LPAs.
- `JsTs_input_functions.json`, `otherlang_input_functions.json`: equivalents
  for JavaScript/TypeScript and other non-Rust languages.
- `llm_api_functions.json`: LLM SDK call signatures (async-openai,
  ollama-rs, gemini-rust, anthropic, etc.). Each entry is annotated with a
  `verified_via` tag indicating whether the signature was confirmed against
  upstream crate docs or is still pending verification.

## License

Dual licensed under MIT or Apache-2.0 per the bundled `LICENSE` file.
