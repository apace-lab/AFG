//! Scratch crate compiled for real against `anthropic-sdk` 0.1.5 to
//! regenerate `ir_output.ll` and confirm the ABI shape catalogued in
//! `datasets/llm_api_functions.json` for `anthropic_sdk::Request::execute`.
//! Compiled with `cargo rustc --lib -- --emit=llvm-ir -C debuginfo=0` under
//! rustc 1.86.0 (bundles LLVM 19.1.7, matching this repo's pinned
//! `llvm-ir`/`llvm-sys` deps). See `LLM_API_IR_VERIFICATION.md` at the repo
//! root for the methodology, and `examples/src/ac_demo_llvm/my_app.rs` for
//! the style this mirrors.
//!
//! The call is driven through `tokio::runtime::Runtime::block_on` from a
//! plain (non-async) `pub fn` rather than left as a bare `pub async fn` --
//! see `IR_SourceCode/ollama-rs/src/lib.rs` for why: an un-polled async
//! fn's body compiles to a trivial coroutine-constructor stub only, with
//! the real call sequence never emitted.

use anthropic_sdk::Client;
use serde_json::json;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

pub fn call_send_message(api_key: &str) {
    rt().block_on(async {
        let request = Client::new()
            .auth(api_key)
            .model("claude-3-5-sonnet-20241022")
            .messages(&json!([
                {"role": "user", "content": "Hello, Claude!"}
            ]))
            .max_tokens(1024)
            .build()
            .unwrap();

        let prefix = String::from("chunk: ");
        let _ = request
            .execute(move |text: String| {
                let prefix = prefix.clone();
                async move {
                    println!("{prefix}{text}");
                }
            })
            .await;
    });
}
