# Expected results: chatgpt_mir.txt

Run:

```sh
./target/release/find_llm_calls --mir examples/chatgpt_mir.txt
```

## Terminal output

```
[find_llm_calls] loaded 31 signatures from datasets/llm_api_functions.json
No LLM API calls found in examples/chatgpt_mir.txt
[find_llm_calls] JSON written to llm_api_matches.json
```

## JSON output

```json
{
  "matches": [],
  "mir_file": "examples/chatgpt_mir.txt",
  "signatures_loaded": 31,
  "total_matches": 0
}
```

## What this shows

Zero matches is the correct result for this file. The MIR is from a Tauri
desktop app whose `main` function sets up the Tauri runtime and registers
plugins — the actual OpenAI API calls happen inside Tauri command handlers
that RUPTA did not trace from this entry point.

This is an expected limitation of static analysis: calls reachable only
through dynamic dispatch or framework-managed threads may not appear in the
MIR dump. To find them, re-run RUPTA with the command handler function as the
entry point instead of `main`.
