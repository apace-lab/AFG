# Expected results: tabby_direct_mir.txt

Run:

```sh
./target/release/find_llm_calls --mir examples/tabby_direct_mir.txt
```

## Terminal output

```
[find_llm_calls] loaded 31 signatures from datasets/llm_api_functions.json
Found 1 LLM API call(s) in examples/tabby_direct_mir.txt:

  Found async-openai API call (async_openai::chat::Chat::create) at FuncId(928) (chat_harness::main::{closure#0}<std::future::ResumeTy, (), (), CoroutineWitness(DefId(0:4 ~ chat_harness[7f78]::main::{closure#0}), []), ()>) / bb5 [line 68563]
[find_llm_calls] JSON written to llm_api_matches.json
```

## JSON output

```json
{
  "matches": [
    {
      "callsite": {
        "basic_block": "bb5",
        "func_id": "FuncId(928)",
        "function": "chat_harness::main::{closure#0}<std::future::ResumeTy, (), (), CoroutineWitness(DefId(0:4 ~ chat_harness[7f78]::main::{closure#0}), []), ()>",
        "line": 68563
      },
      "fn_name": "async_openai::chat::Chat::create",
      "library": "async-openai",
      "match_strategy": "short-name",
      "raw_line": "_7 = async_openai_alt::Chat::<'_, async_openai_alt::config::OpenAIConfig>::create(move _8, move _10) -> [return: bb6, unwind: bb18];"
    }
  ],
  "mir_file": "examples/tabby_direct_mir.txt",
  "signatures_loaded": 31,
  "total_matches": 1
}
```

## What this shows

This MIR is from TabbyML's chat harness, which uses a renamed version of the
async-openai crate (`async_openai_alt`) with a generic config type parameter
on the receiver (`Chat::<'_, OpenAIConfig>::create`).

The tool detects the call correctly via `short-name` after stripping the
mid-path generic arguments. Without turbofish stripping, this call site would
be missed entirely — it is the primary real-world test case for that feature.
