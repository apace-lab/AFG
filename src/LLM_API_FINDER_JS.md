# LLM API Finder (JS/TS)

Companion to [`find_llm_calls`](./LLM_API_FINDER.md). Scans JavaScript/
TypeScript **source text** directly — no MIR/RUPTA step, since RUPTA only
understands Rust. This is what catches LLM calls made from the frontend of a
Tauri/Electron-style "Rust" app, which never appear in the compiled Rust
binary at all.

## Supported libraries

| Library | Packages | Notes |
|---|---|---|
| `openai` | `openai` | chat/completions, embeddings, images, audio |
| `anthropic` | `@anthropic-ai/sdk` | Messages API |
| `google-genai` | `@google/generative-ai`, `@google/genai` | generateContent, chat sessions |
| `groq-sdk` | `groq-sdk` | OpenAI-compatible shape |
| `cohere-ai` | `cohere-ai` | chat/generate/embed/rerank — import required |
| `mistralai` | `@mistralai/mistralai` | chat, embeddings |
| `ollama-js` | `ollama` | chat/generate/embeddings — import required |
| `vercel-ai-sdk` | `ai` | generateText/streamText/generateObject/streamObject |
| `langchain-js` | `langchain`, `@langchain/*` | invoke/predict/call — import required |
| `raw-http-fetch` | — | `fetch`/`axios`/`http(s).request`, reported when a known LLM REST path is nearby |

These come from general knowledge of each SDK's API shape and haven't been
re-verified against current docs — spot-check against the target's
`package.json` before trusting a result.

## Build

```sh
cargo build --release
```

Produces `find_llm_calls_js` in `target/release/`.

## Quick example

```sh
./target/release/find_llm_calls_js --src examples/src/chat.ts
```

```
Found 3 LLM API call(s) in examples/src/chat.ts:

  Found groq-sdk call (chat.completions.create, chat completion (OpenAI-compatible shape)) at examples/src/chat.ts:6 [call-only]
  Found openai call (chat.completions.create, chat completion) at examples/src/chat.ts:6 [call+import]
  Found raw-http-fetch call (fetch, raw HTTP call) at examples/src/chat.ts:15 [http+path-hint]
    provider hint: Anthropic (Claude Messages API)
```

The `openai`/`groq-sdk` double-hit on one line isn't a bug — both SDKs share
the identical `chat.completions.create` shape (groq-sdk is
OpenAI-compatible by design). The file's import only confirms `openai`, so
it's marked `call+import` while `groq-sdk` is the weaker `call-only`.

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
| `--all-http-calls` | no | off | Report every `fetch`/`axios`/`http(s).request` call, even with no known LLM path nearby |
| `--include-node-modules` | no | off | Also scan `node_modules` |

Walks `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs` files, skipping `.git` and
(by default) `node_modules`. `.vue`/`.svelte` files aren't scanned directly
— extract the `<script>` block first.

## Match strategies

- `call+import` — call shape matched, and the file imports the SDK. High confidence.
- `call-only` — call shape matched, no confirming import found in this file (bundlers often strip imports but leave the call chain intact).
- `http+path-hint` — a `fetch`/`axios`/`http(s).request` call with a known LLM REST path nearby.
- `http-call-only` — same call, no known path nearby — only reported with `--all-http-calls`.

Generic one-word patterns like `chat(`/`invoke(` are only reported when the
file also imports the matching package (`"require_import": true` in the
dataset) — otherwise they're too common in unrelated code to be useful.
Distinctive multi-segment chains (`chat.completions.create`) are reported
unconditionally.

## Relationship to `find_llm_calls`

Both tools emit the same JSON shape (`library`, `match_strategy`,
`callsite`, `raw_line`, optional `provider_hint`), so results can be
concatenated for a whole-app view. They don't share a call graph — a JS call
into a Tauri command that itself calls an LLM from Rust shows up once in
each report, unlinked.

### Running both scans together: `find_llm_calls_all`

```sh
./target/release/find_llm_calls_all \
    --mir /tmp/my_program_mir.txt \
    --src path/to/frontend/src \
    --out llm_api_matches_all.json
```

Either `--mir` or `--src` may be omitted (at least one required).
`--all-http-calls`/`--include-node-modules` are forwarded to the JS/TS
stage. Output has `rust_matches`/`js_matches`/`total_matches`.

## Troubleshooting

**Datasets file not found** — run from the `AFG/` directory, or pass
`--datasets /path/to/AFG/datasets`.

**Zero matches on an app you know calls an LLM from JS** — check for a
dynamically constructed property path (`client[method]()`) or a re-exported
wrapper with a different name; text matching can't see through either. Also
check whether the code is server-side (bundled separately) rather than
shipped in the client bundle you scanned.

**Too many `raw-http-fetch` matches** — drop `--all-http-calls`.

**A `call-only` match looks wrong** — generic single-word patterns can hit
unrelated code. Read `raw_line`, and check whether another file imports the
SDK under a different local binding.
