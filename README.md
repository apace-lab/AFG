# afg

Access Flow Guard (AFG) is a framework for detecting cross-user data leaks in
multi-user Rust programs, in particular LLM-powered applications that share
caches, databases, or other global state across user sessions.

This repository is the MIR-based implementation of AFG. It consumes rupta's
Rust MIR pointer-analysis output and reports the set of abstract objects that
are reachable from more than one user, which are the candidate leak sites in
the paper's terminology.

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

The tool itself is a post-pass: it runs after rupta has already computed the
points-to graph, so it does not touch rupta's source and does not pay the
cost of re-analyzing the program.

## How it fits with rupta

Rupta (https://github.com/rustanlys/rupta) is an external project that
performs Andersen-style or k-callsite-sensitive pointer analysis over Rust
MIR. `afg` treats rupta as a black box, reads the points-to text dump rupta
produces (`--dump-pts`), and applies the AFG-specific taint-tagging and
overlap detection on top of it.

The earlier AFG prototype operated on LLVM IR through a C++ LLVM pass.
Switching to MIR removes the symbol-demangling step, preserves Rust-level
type and path information, and lets us inherit rupta's handling of Rust
constructs such as closures, trait dispatch, and monomorphization.

## Build

```sh
cargo build --release
```

Stable Rust. Dependencies: `serde`, `serde_json`, `clap`. The release binary
is produced at `target/release/afg`.

## Usage

```sh
afg --pts <rupta_pts_dump> --config <mump_config.json> [--verbose]
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

Run directly on the included sample, with no rupta installation needed:

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

Install rupta first. The bundled `demo/` directory is the reference Rust
program the sample dump was derived from. It pins rupta's nightly via its
own `rust-toolchain.toml`.

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
  Maps to `FuncId(N)::local_M` in rupta's dump.
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

- `FuncId(N)` identifies a monomorphized function in rupta's index.
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

## Measured performance on the demo

End-to-end, from Rust source to overlap report, running on the AFG demo:

| Stage                         | Value                 |
|-------------------------------|-----------------------|
| Rupta call graph (CS edges)   | 489                   |
| Rupta reachable functions     | 354                   |
| Rupta points-to relations     | 1328                  |
| Rupta analysis time           | 149 ms                |
| `afg` parse time              | 308 us                |
| `afg` fixed-point time        | 95 us (4 iterations)  |
| `afg` total post-pass time    | 810 us                |
| Cross-user overlap nodes      | 3 (all true positive) |

## Limitations

- Function name matching in the config is exact. If the pts dump lists a
  monomorphized entry like
  `async_openai::chat::Chat<OpenAIConfig>::create`, the config must use that
  exact string. A future revision should accept a prefix or regex form.
- Taint propagation is context-insensitive at the post-pass layer because
  rupta's text dump flattens contexts. For finer distinctions (for example,
  separating the same function called from two call sites), origin tags
  should be computed inside rupta on the context-sensitive pts-set, rather
  than in this post-pass.
- The tool treats the full points-to relation as one graph. Access-control
  policies that statically block flow on specific edges are not yet modeled.
  This is Stage 3 of the AFG framework, dynamic refinement.
- The tool does not yet model LLM API calls as summarized black boxes. The
  conservative rule (all outputs tainted by all inputs) is implied by
  seeding the call's parameters and treating its return value as tainted,
  but field-level summary models are not expressed here yet.

## File layout

```
afg/
    Cargo.toml              stable Rust, 3 crate deps
    src/main.rs             parser, fixed-point, overlap report
    examples/
        demo_pts.sample.txt sample rupta dump from the demo program
        mump_config.json    matching user config for the demo
    demo/                   reference Rust program the sample was generated from
        Cargo.toml
        rust-toolchain.toml pins rupta's nightly
        src/main.rs         two threads sharing Arc<Mutex<HashMap>>
    datasets/               MUMP reference datasets (signature catalogues)
        rust_input_functions.json
        JsTs_input_functions.json
        otherlang_input_functions.json
        llm_api_functions.json
    LICENSE
    README.md
    .gitignore
```

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
