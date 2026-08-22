# IR source code

One tiny scratch crate per SDK in `datasets/llm_api_functions.json`, each
compiled for real to reproduce the LLVM IR that verification pass read —
see `LLM_API_IR_VERIFICATION.md` at the repo root for the methodology, and
`SIGNATURE_CATEGORIES.md` for how the catalogue's `sret`/`request_index`
fields came from it. The original scratch crates used for that pass were
ephemeral and never committed; these were regenerated afterward so the
source and IR persist in the repo.

Each `IR_SourceCode/<sdk>/` is a standalone `cargo new --lib` crate (the
repo root `Cargo.toml` has no `[workspace]`, so these don't interact with
the main `afg` package) containing:

- `Cargo.toml` — the SDK pinned to the exact version the catalogue was
  verified against
- `rust-toolchain.toml` — pins the rustc version used (1.86.0 for all but
  `misanthropic`, which needs 1.88.0 — see below)
- `src/lib.rs` — plain functions calling each catalogued function with
  plausible arguments; written to typecheck and compile, not to run
  correctly
- `ir_output.ll` — the real LLVM IR from
  `cargo rustc --lib -- --emit=llvm-ir -C debuginfo=0`

`target/` build caches were deleted after copying out `ir_output.ll` (not
gitignored content worth keeping — multi-hundred-MB each across 9 SDKs).
Regenerate by running the same `cargo rustc` command from inside any
`<sdk>/` directory.

## Per-SDK notes

| SDK | Version | rustc | Verified |
|---|---|---|---|
| `async-openai` | 0.41.3 | 1.86.0 | all 13 entries match exactly |
| `ollama-rs` | 0.3.6 | 1.86.0 | all 6 entries match exactly |
| `clust` | 0.9.0 | 1.86.0 | both entries match exactly (byte-for-byte sret size) |
| `rig-core` | 0.16.0 | 1.86.0 | both entries match exactly (0.17.1+ needs rustc ≥1.88 for let-chains, can't compile here) |
| `gemini-rust` | 2.0.0 | 1.86.0 | all 3 entries match byte-for-byte |
| `anthropic-sdk` | 0.1.5 | 1.86.0 | matches exactly |
| `misanthropic` | 1.0.0-alpha.16 | **1.88.0** (needs let-chains; bundles LLVM 20.1.x, not 19) | shape matches; sret byte size differs slightly (1192 vs 1280) because it's LLVM 20 not 19 |
| `llm-chain` (+ `llm-chain-openai`) | 0.13.0 | 1.86.0 | both entries match exactly — confirms `Executor::execute` really has no sret (async_trait-boxed) while `Chain::run` does |
| `genai` | 0.3.5 | 1.86.0 | both entries match exactly (0.4.0+ needs rustc ≥1.88 for let-chains) |
| `raw-http-reqwest` (`reqwest`) | 0.13.4 | 1.86.0 | both variants match — confirms async `send()` has no sret, blocking `send()` does |

## A gotcha every one of these hit

A bare `pub async fn` wrapper that calls the target method and `.await`s it
is not enough — debug-mode `--emit=llvm-ir` only codegens an async fn's
*outer* symbol (which just constructs a suspended coroutine); the real
body, including the call you want to see, lives in a separate `poll` item
that rustc's mono-item collector won't emit unless something in the crate
actually drives that future to completion. Every one of these crates needed
an explicit driver — `futures::executor::block_on`, a manual `Waker::noop`
+ one `poll()` call, or `tokio::runtime::Runtime::block_on` — wrapping the
async call before the real call site would appear in the `.ll` output at
all. Worth knowing before regenerating any of these, or writing a new one
for a future SDK.
