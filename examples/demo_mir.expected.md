# Expected results: demo_mir.txt

Run:

```sh
./target/release/find_llm_calls --mir examples/demo_mir.txt
```

## Terminal output

```
[find_llm_calls] loaded 28 signatures from datasets/llm_api_functions.json
Found 2 LLM API call(s) in examples/demo_mir.txt:

  Found raw-http-reqwest API call (reqwest::RequestBuilder::send) at FuncId(11) (demo::call_openai_direct) / bb28 [line 1294]
  Found async-openai API call (async_openai::chat::Chat::create) at FuncId(78) (demo::call_chatgpt_api) / bb0 [line 5874]
[find_llm_calls] JSON written to llm_api_matches.json
```

## JSON output

```json
{
  "matches": [
    {
      "callsite": {
        "basic_block": "bb28",
        "func_id": "FuncId(11)",
        "function": "demo::call_openai_direct",
        "line": 1294
      },
      "fn_name": "reqwest::RequestBuilder::send",
      "library": "raw-http-reqwest",
      "match_strategy": "short-name",
      "raw_line": "_41 = reqwest::blocking::RequestBuilder::send(const reqwest::blocking::RequestBuilder) -> [return: bb29, unwind: bb40];"
    },
    {
      "callsite": {
        "basic_block": "bb0",
        "func_id": "FuncId(78)",
        "function": "demo::call_chatgpt_api",
        "line": 5874
      },
      "fn_name": "async_openai::chat::Chat::create",
      "library": "async-openai",
      "match_strategy": "short-name",
      "raw_line": "_3 = async_openai_stub::chat::Chat::create(_1, const async_openai_stub::CreateChatCompletionRequest) -> [return: bb1, unwind continue];"
    }
  ],
  "mir_file": "examples/demo_mir.txt",
  "signatures_loaded": 28,
  "total_matches": 2
}
```

## What this shows

The demo program makes LLM calls two different ways:

1. **`demo::call_openai_direct`** — sends a raw HTTP request using `reqwest` instead of an SDK. Detected as `raw-http-reqwest` via `short-name` match because the MIR emits the blocking variant (`reqwest::blocking::RequestBuilder::send`) which shares the last two path segments with the catalogue entry.

2. **`demo::call_chatgpt_api`** — uses the `async-openai` SDK via a stub crate (`async_openai_stub`). Detected via `short-name` match because the stub crate has a different crate prefix but the same struct and method name (`Chat::create`).
