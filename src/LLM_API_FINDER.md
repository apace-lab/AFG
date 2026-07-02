# LLM API Finder

A tool that scans a Rust program's compiled output and reports every location
where it calls an LLM (OpenAI, Ollama, Gemini, Anthropic, etc.). No source
code changes required — it works from RUPTA's static analysis output.

## What it does

Given a program analysis file (MIR dump), `find_llm_calls` tells you:

- **Which LLM library** is being called (e.g. `async-openai`, `ollama-rs`)
- **Which function** in the program makes the call
- **Where exactly** in the code that call occurs

Results are printed to the terminal and saved as a JSON file for downstream
use in the [AFG](../README.md) pipeline.

## Supported libraries

| Library | What it covers |
|---|---|
| `async-openai` | OpenAI chat, completions, embeddings, images, audio |
| `ollama-rs` | Ollama generate, chat, embeddings |
| `gemini-rust` | Gemini content generation and conversation |
| `anthropic-sdk` | Anthropic Claude messages |
| `misanthropic` | Anthropic Claude (alternate client) |
| `llm-chain` | LLM chain executor and sequential chains |
| `genai` | Multi-provider genai client |
| `raw-http-reqwest` | Direct HTTP calls to LLM APIs (no SDK) |

## Build

```sh
cargo build --release
```

Produces two binaries in `target/release/`: `afg` (the main leak detector) and
`find_llm_calls` (this tool).

## Quick example

Run against the bundled demo:

```sh
./target/release/find_llm_calls --mir examples/demo_mir.txt
```

Output:

```
Found 2 LLM API call(s) in examples/demo_mir.txt:

  Found raw-http-reqwest API call (reqwest::RequestBuilder::send) at FuncId(11) (demo::call_openai_direct) / bb28 [line 1294]
  Found async-openai API call (async_openai::chat::Chat::create) at FuncId(78) (demo::call_chatgpt_api) / bb0 [line 5874]
```

A JSON report is also written to `llm_api_matches.json` automatically.

## Usage

```sh
# release build (faster)
./target/release/find_llm_calls --mir <MIR_DUMP> [--datasets <DIR>] [--out <FILE>]

# or with cargo directly (no separate build step needed)
cargo run --bin find_llm_calls -- --mir <MIR_DUMP> [--datasets <DIR>] [--out <FILE>]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--mir` | yes | — | Path to the RUPTA MIR dump to scan |
| `--datasets` | no | `datasets/` | Folder containing `llm_api_functions.json` |
| `--out` | no | `llm_api_matches.json` | Where to write the JSON report |

## Generating a MIR dump

`find_llm_calls` reads output from [RUPTA](https://github.com/rustanlys/rupta),
a Rust static analysis tool. To analyze your own program:

1. Install RUPTA (see its repo for setup instructions).
2. From your project directory:
   ```sh
   cargo pta -- --entry-func main --dump-mir /tmp/my_program_mir.txt
   ```
3. Run the finder:
   ```sh
   ./target/release/find_llm_calls --mir /tmp/my_program_mir.txt
   ```

## JSON output

Each match in `llm_api_matches.json` looks like:

```json
{
  "library": "raw-http-reqwest",
  "fn_name": "reqwest::RequestBuilder::send",
  "match_strategy": "short-name",
  "callsite": {
    "func_id": "FuncId(11)",
    "function": "demo::call_openai_direct",
    "basic_block": "bb28",
    "line": 1294
  },
  "raw_line": "_41 = reqwest::blocking::RequestBuilder::send(...)"
}
```

- `library` — which LLM library was detected
- `fn_name` — the specific function that was called
- `callsite.function` — the Rust function in your program that made the call
- `callsite.line` — line number in the MIR dump for reference
- `raw_line` — the exact line from the analysis output that matched

## Adding a new library

Edit `datasets/llm_api_functions.json` — no rebuild needed. Add an entry under
the library name with the function's full Rust path:

```json
"my-llm-sdk": [
  {
    "fn_name": "my_llm_sdk::Client::complete",
    "return_type": "Result<Response, Error>",
    "parameter_type": ["&self", "Request"],
    "verified_via": "manual"
  }
]
```

## Troubleshooting

**Datasets file not found** — run from the `AFG/` directory, or pass
`--datasets /path/to/AFG/datasets`.

**Zero matches on a program that uses an LLM** — grep the MIR dump for your
SDK's crate name to confirm RUPTA included that call. Dead code, conditional
compilation, or dynamic dispatch can cause calls to be omitted. If the library
isn't in the catalogue yet, add it (see above).

**A match looks wrong** — check `match_strategy` in the output. `short-name`
matches on the last two path segments only, which can occasionally hit
unrelated code with the same method name. Read `raw_line` to confirm.
