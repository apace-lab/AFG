# LLM API Finder

Scans a Rust program's compiled MIR for every call into an LLM SDK (OpenAI,
Ollama, Anthropic, Gemini, ...). No source changes required — it reads
[RUPTA](https://github.com/rustanlys/rupta)'s static-analysis output.

For the JS/TS side of a mixed Rust+frontend app, see
[`find_llm_calls_js`](./LLM_API_FINDER_JS.md) — RUPTA only analyzes Rust.

## Supported libraries

| Library | What it covers |
|---|---|
| `async-openai` | OpenAI chat, completions, embeddings, images, audio |
| `ollama-rs` | Ollama generate, chat, embeddings |
| `clust` | Anthropic Claude messages (unofficial client) |
| `rig-core` | Multi-provider framework (Anthropic, OpenAI, Gemini, Cohere, Mistral, xAI, DeepSeek, Groq, Ollama, ...) |
| `gemini-rust` | Gemini content generation and conversation |
| `anthropic-sdk` | Anthropic Claude messages |
| `misanthropic` | Anthropic Claude (alternate client) |
| `llm-chain` | LLM chain executor and sequential chains |
| `genai` | Multi-provider genai client |
| `raw-http-reqwest` | Direct HTTP calls to LLM APIs (no SDK) |

Cohere, Mistral, and AWS Bedrock have no standalone Rust SDK with meaningful
adoption yet — they're reached in practice through `genai`/`rig-core` above.

## Build

```sh
cargo build --release
```

Produces `find_llm_calls` in `target/release/` alongside `afg`.

## Quick example

```sh
./target/release/find_llm_calls --mir examples/demo_mir.txt
```

```
Found 2 LLM API call(s) in examples/demo_mir.txt:

  Found raw-http-reqwest API call (reqwest::RequestBuilder::send) at FuncId(11) (demo::call_openai_direct) / bb28 [line 1294]
    provider hint: OpenAI-compatible endpoint (OpenAI or a compatible proxy: Ollama, LM Studio, OpenRouter, etc.)
  Found async-openai API call (async_openai::chat::Chat::create) at FuncId(78) (demo::call_chatgpt_api) / bb0 [line 5874]
```

A JSON report is also written, to `llm_api_matches.json` by default.

## Usage

```sh
./target/release/find_llm_calls --mir <MIR_DUMP> [--datasets <DIR>] [--out <FILE>]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--mir` | yes | — | Path to the RUPTA MIR dump to scan |
| `--datasets` | no | `datasets/` | Folder containing `llm_api_functions.json` |
| `--out` | no | `llm_api_matches.json` | Where to write the JSON report |

## Generating a MIR dump

1. Install [RUPTA](https://github.com/rustanlys/rupta) (see its repo for setup).
2. From your project directory:
   ```sh
   cargo pta -- --entry-func main --dump-mir /tmp/my_program_mir.txt
   ```
3. Run the finder:
   ```sh
   ./target/release/find_llm_calls --mir /tmp/my_program_mir.txt
   ```

## JSON output

```json
{
  "library": "raw-http-reqwest",
  "fn_name": "reqwest::RequestBuilder::send",
  "category": "llm-api-chat",
  "match_strategy": "short-name",
  "callsite": {
    "func_id": "FuncId(11)",
    "function": "demo::call_openai_direct",
    "basic_block": "bb28",
    "line": 1294
  },
  "raw_line": "_41 = reqwest::blocking::RequestBuilder::send(...)",
  "provider_hint": "OpenAI-compatible endpoint (OpenAI or a compatible proxy: Ollama, LM Studio, OpenRouter, etc.)"
}
```

- `library` / `fn_name` — which LLM library and function was detected
- `category` — `llm-api-prompt` (assembling the request — message/content
  builders, e.g. `ChatCompletionRequestUserMessageArgs::content`) or
  `llm-api-chat` (the outbound call that actually sends it, e.g.
  `Chat::create`). Lets you tell "this program is preparing a prompt" apart
  from "this program is calling out to an LLM" without reading `fn_name` by
  hand. `unspecified` on a catalogue entry that predates this split — treat
  it as `llm-api-chat`.
- `callsite.function` / `callsite.line` — where in your program, and where
  in the MIR dump, the call was found
- `raw_line` — the exact line from the analysis output that matched
- `provider_hint` — present only on `raw-http-reqwest` matches, where
  `library` alone just says "some code called `reqwest`". Guessed from a
  known REST path suffix seen in a nearby string literal (`/messages` →
  Anthropic, `/chat/completions` → OpenAI-compatible, `:generateContent` →
  Gemini, `/api/generate`/`/api/chat` → Ollama). Absent means no known
  suffix was found nearby, not that the call isn't LLM-related.

## Adding a new library

Edit `datasets/llm_api_functions.json` — no rebuild needed. `category` splits
entries into `llm-api-prompt` (assembling the request) and `llm-api-chat`
(sending it) — see the file's own `_schema_notes` for the full convention,
including when `parameter_type` needs a leading `"sret"` slot. A `find_llm_calls`
match only ever carries `library`/`fn_name`/`category` (see [JSON
output](#json-output) above); `return_type`/`parameter_type`/`request_index`/
`prompt_arg_index`/`prompt_role` are catalogue-only metadata that `find_llm_calls`
doesn't read at all — they exist purely for a downstream consumer (RUPTA) that
reads the JSON file directly, so get them right even though this tool's own
matching won't notice if they're wrong:

```json
"my-llm-sdk": [
  {
    "fn_name": "my_llm_sdk::MessageBuilder::content",
    "category": "llm-api-prompt",
    "return_type": "&mut MessageBuilder",
    "parameter_type": ["&mut self", "impl Into<String>"],
    "prompt_arg_index": 1,
    "prompt_role": "user",
    "verified_via": "manual"
  },
  {
    "fn_name": "my_llm_sdk::Client::complete",
    "category": "llm-api-chat",
    "return_type": "Result<Response, Error>",
    "parameter_type": ["sret", "&self", "Request"],
    "request_index": 2,
    "verified_via": "manual"
  }
]
```

`"sret"` is prepended to `parameter_type`, and every real argument shifts one
slot later, whenever the real compiled signature returns its `Result`
indirectly through a caller-allocated pointer — true for most `Result<T, E>`-returning
methods here, but confirm against real `--emit=llvm-ir` output rather than
assuming: a plain `fn` returning `impl Future<...>` directly (not a native
`async fn`) can skip `sret` entirely if the concrete future type is small
enough to fit in registers. See `_schema_notes.async_sret_caveat` in the
dataset and [`../LLM_API_IR_VERIFICATION.md`](../LLM_API_IR_VERIFICATION.md)
for worked examples of both shapes.

## Troubleshooting

**Datasets file not found** — run from the `AFG/` directory, or pass
`--datasets /path/to/AFG/datasets`.

**Zero matches on a program that uses an LLM** — grep the MIR dump for your
SDK's crate name to confirm RUPTA included that call; dead code, conditional
compilation, or dynamic dispatch can cause calls to be omitted. If the
library isn't catalogued yet, add it (above).

**A match looks wrong** — check `match_strategy`. `short-name` matches on
the last two path segments only and can occasionally hit unrelated code;
read `raw_line` to confirm.

**RUPTA won't compile the target program** — RUPTA pins a specific nightly
toolchain (see its `rust-toolchain.toml`). A target requiring a newer
compiler (most commonly `edition = "2024"`) won't build under RUPTA, so it
can't produce a MIR dump — there's no workaround via this tool's flags. As a
fallback, grep the target's source for the crate names in "Supported
libraries" and check call sites by hand against `datasets/llm_api_functions.json`.
