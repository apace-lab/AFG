//! Scratch crate compiled for real against `anthropic-sdk` 0.1.5 to
//! regenerate `ir_output.ll` and confirm the ABI shape catalogued in
//! `datasets/llm_api_functions.json` for `anthropic_sdk::Request::execute`.
//! Compiled with `cargo rustc --lib -- --emit=llvm-ir -C debuginfo=0` under
//! rustc 1.86.0 (bundles LLVM 19.1.7, matching this repo's pinned
//! `llvm-ir`/`llvm-sys` deps). See `LLM_API_IR_VERIFICATION.md` at the repo
//! root for the methodology, and `examples/src/ac_demo_llvm/my_app.rs` for
//! the style this mirrors.

use anthropic_sdk::Client;
use serde_json::json;

pub async fn send_message(api_key: &str) -> Result<(), anyhow::Error> {
    let request = Client::new()
        .auth(api_key)
        .model("claude-3-5-sonnet-20241022")
        .messages(&json!([
            {"role": "user", "content": "Hello, Claude!"}
        ]))
        .max_tokens(1024)
        .build()?;

    let prefix = String::from("chunk: ");
    request
        .execute(move |text: String| {
            let prefix = prefix.clone();
            async move {
                println!("{prefix}{text}");
            }
        })
        .await
}
