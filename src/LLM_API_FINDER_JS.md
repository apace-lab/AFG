# LLM API Finder (JS/TS)

Companion to [`find_llm_calls`](./LLM_API_FINDER.md), which scans a Rust
program's RUPTA MIR dump. This tool scans JavaScript/TypeScript **source
text** directly — there is no MIR/RUPTA step, because RUPTA only understands
Rust. It exists for the common case where a "Rust" desktop app (Tauri,
Electron-with-a-Rust-sidecar, etc.) does all of its actual LLM chat logic in
the JS/TS frontend and uses Rust only for windowing/OS integration — those
call sites are invisible to `find_llm_calls` no matter how good the Rust-side
analysis is, since they never appear in a compiled Rust binary at all.

## What it does

Given a JS/TS source file or directory, `find_llm_calls_js` tells you:

- **Which LLM library** the call shape matches (e.g. `openai`, `@anthropic-ai/sdk`)
- **Whether an import confirms it** — a distinctive multi-segment call like
  `chat.completions.create` is reported on its own; a generic one-word call
  like `chat(` or `invoke(` is only reported when the file also imports the
  matching SDK package
- **Where exactly** — file and line number
- **Provider guess for raw `fetch`/`axios` calls**, from a known REST path
  suffix found in a nearby string literal (same heuristic table
  `find_llm_calls` uses for raw `reqwest` calls)

Results are printed to the terminal and saved as JSON, in the same shape as
`find_llm_calls`'s output, so both can feed the same downstream AFG pipeline
step.

## Supported libraries

| Library | Packages | Notes |
|---|---|---|
| `openai` | `openai` | chat/completions, embeddings, images, audio |
| `anthropic` | `@anthropic-ai/sdk` | Messages API |
| `google-genai` | `@google/generative-ai`, `@google/genai` | generateContent, chat sessions |
| `groq-sdk` | `groq-sdk` | OpenAI-compatible shape |
| `cohere-ai` | `cohere-ai` | chat/generate/embed/rerank — generic names, import required |
| `mistralai` | `@mistralai/mistralai` | chat, embeddings |
| `ollama-js` | `ollama` | chat/generate/embeddings — generic names, import required |
| `vercel-ai-sdk` | `ai` | generateText/streamText/generateObject/streamObject |
| `langchain-js` | `langchain`, `@langchain/*` | invoke/predict/call — very generic, import required |
| `raw-http-fetch` | — | `fetch`/`axios`/`http(s).request` calls, reported when a known LLM REST path is found nearby |

These signatures come from general knowledge of each SDK's public API shape
and, unlike the Rust catalogue in `llm_api_functions.json`, have **not** been
independently re-verified against current published docs — JS SDKs iterate
faster than the Rust crates this pipeline targets. Spot-check against the
target's actual installed version (`package.json`) before trusting a result.

## Build

```sh
cargo build --release
```

Produces `find_llm_calls_js` in `target/release/` alongside `afg` and
`find_llm_calls`.

## Quick example

```sh
./target/release/find_llm_calls_js --src examples/src/chat.ts
```

Output:

```
Found 3 LLM API call(s) in examples/src/chat.ts:

  Found groq-sdk call (chat.completions.create, chat completion (OpenAI-compatible shape)) at examples/src/chat.ts:6 [call-only]
  Found openai call (chat.completions.create, chat completion) at examples/src/chat.ts:6 [call+import]
  Found raw-http-fetch call (fetch, raw HTTP call) at examples/src/chat.ts:15 [http+path-hint]
    provider hint: Anthropic (Claude Messages API)
```

The `openai`/`groq-sdk` double-hit on the same line is not a bug: both SDKs
share the identical `chat.completions.create` call shape (groq-sdk is
OpenAI-compatible by design), and the file's import only confirms `openai` —
so both are reported, with `openai` marked `call+import` and `groq-sdk`
marked `call-only` (unconfirmed). This is genuine ambiguity from the SDK
market, not scanner noise; a suffix pattern that's a strict substring of
another match from the *same* library (e.g. `openai`'s legacy
`completions.create` inside `chat.completions.create`) is deduplicated
automatically.

A JSON report is written to `llm_api_matches_js.json` by default.

## Usage

```sh
./target/release/find_llm_calls_js --src <PATH> [--datasets <DIR>] [--out <FILE>] [--all-http-calls] [--include-node-modules]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--src` | yes | — | JS/TS source file or directory to scan |
| `--datasets` | no | `datasets/` | Folder containing `llm_api_functions_js.json` |
| `--out` | no | `llm_api_matches_js.json` | Where to write the JSON report |
| `--all-http-calls` | no | off | Report every `fetch`/`axios`/`http(s).request` call, even without a known LLM path nearby |
| `--include-node-modules` | no | off | Also scan `node_modules` (usually noise — vendored code, not the target's own) |

Directory scans walk `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` files and
skip `.git` and (by default) `node_modules`. `.vue`/`.svelte` single-file
components are not scanned directly — extract the `<script>` block first if
needed.

## Match strategies

- `call+import` — a call-shape pattern matched, and the file also imports the
  SDK package it belongs to. High confidence.
- `call-only` — the call-shape pattern matched but no confirming import was
  found in this file. Not discarded, because bundlers frequently strip or
  rewrite import statements while leaving property-access chains
  (`x.chat.completions.create(`) intact in the output — but treat it as a
  weaker signal, especially for generic patterns.
- `http+path-hint` — a `fetch`/`axios`/`http(s).request` call with a known
  LLM REST path suffix (`/chat/completions`, `/messages`,
  `:generateContent`, `/api/generate`, `/api/chat`) found in a string literal
  within a few lines of the call.
- `http-call-only` — same call, but no known path found nearby. Only
  reported with `--all-http-calls`, since unconditional `fetch()` reporting
  in ordinary frontend code is mostly noise.

## Why call-shape patterns like `chat(` require an import

Method names like `chat`, `generate`, `invoke`, or `call` are common English
words that show up constantly in code that has nothing to do with LLMs (UI
event handlers, unrelated business logic, etc.). Entries in
`llm_api_functions_js.json` marked `"require_import": true` are gated: they
are only reported when the same file also imports one of that library's
`packages`. Distinctive multi-segment chains (`chat.completions.create`,
`generateContentStream`) are specific enough to report unconditionally.

## Relationship to `find_llm_calls`

Both tools write structurally similar JSON (`library`, a call
identifier, `match_strategy`, a `callsite`, `raw_line`, optional
`provider_hint`), so results can be concatenated or diffed for a
whole-application view of a Tauri-style app: `find_llm_calls` covers the
Rust/native side, `find_llm_calls_js` covers the webview/frontend side. They
do not share a call graph — a JS call that invokes a Tauri command which
itself calls an LLM from Rust will show up once in each report, at each
language's respective call site, with no automatic linkage between the two.

### Running both scans together: `find_llm_calls_all`

`find_llm_calls_all` runs the Rust MIR scan first, then the JS/TS source scan
right after it, and writes one merged JSON report — this is the pipeline
entry point for a mixed Rust+frontend target:

```sh
./target/release/find_llm_calls_all \
    --mir /tmp/my_program_mir.txt \
    --src path/to/frontend/src \
    --out llm_api_matches_all.json
```

Either `--mir` or `--src` may be omitted to run a single-language scan (at
least one is required). `--all-http-calls` and `--include-node-modules` are
forwarded to the JS/TS stage. The output JSON has `rust_matches` and
`js_matches` arrays plus a combined `total_matches` count; each stage also
prints its own findings to stdout in the order it ran (Rust first, then
JS/TS), so `find_llm_calls_all`'s output is a strict superset of running
`find_llm_calls` and `find_llm_calls_js` separately.

## Troubleshooting

**Datasets file not found** — run from the `AFG/` directory, or pass
`--datasets /path/to/AFG/datasets`.

**Zero matches on an app you know calls an LLM from JS** — check whether the
frontend calls the SDK through a dynamically constructed property path
(`client[method]()`) or via a re-exported wrapper function with a different
name; text-pattern matching can't see through either. Also check whether the
code path is server-side (a Next.js API route bundled separately) rather
than shipped in the client bundle you scanned.

**Too many `raw-http-fetch` matches** — you likely passed
`--all-http-calls`; drop the flag to require a known LLM path hint.

**A `call-only` match looks wrong** — generic single-word patterns can hit
unrelated code (a UI `chat()` helper, a queue's `invoke()`). Read `raw_line`
and, if it's marked `require_import` in the dataset but you still got a hit,
check whether another file in the same bundle imports the SDK under a
different local binding.
