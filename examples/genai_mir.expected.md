# Expected results: genai_mir.txt

Run:

```sh
./target/release/find_llm_calls --mir examples/genai_mir.txt
```

## Terminal output

```
[find_llm_calls] loaded 31 signatures from datasets/llm_api_functions.json
Found 1 LLM API call(s) in examples/genai_mir.txt:

  Found genai API call (genai::Client::exec_chat) at FuncId(0) (genai_demo::run) / bb0 [line 12]
[find_llm_calls] JSON written to llm_api_matches.json
```

## JSON output

```json
{
  "matches": [
    {
      "callsite": {
        "basic_block": "bb0",
        "func_id": "FuncId(0)",
        "function": "genai_demo::run",
        "line": 12
      },
      "fn_name": "genai::Client::exec_chat",
      "library": "genai",
      "match_strategy": "direct",
      "raw_line": "_4 = genai::Client::exec_chat(move _1, const \"llama3\", move _2, move _3) -> [return: bb1, unwind: bb2];"
    }
  ],
  "mir_file": "examples/genai_mir.txt",
  "signatures_loaded": 31,
  "total_matches": 1
}
```

## What this shows

A minimal program using the `genai` multi-provider client to call `exec_chat`.
The match strategy is `direct` — the full path `genai::Client::exec_chat`
appears verbatim in the MIR, which is the highest-confidence match type.
