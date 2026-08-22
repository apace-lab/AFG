//! Scratch crate used solely to compile real calls against the real
//! `clust` crate (the Anthropic Claude Rust SDK) and inspect the emitted
//! LLVM IR for `datasets/llm_api_functions.json`'s "clust" entries. See
//! `LLM_API_IR_VERIFICATION.md` at the repo root for the methodology.
//!
//! Mirrors the style of `examples/src/ac_demo_llvm/my_app.rs`: plain
//! functions that call the catalogued SDK methods with plausible (not
//! necessarily runnable) arguments, compiled in debug mode so the calls
//! aren't inlined away before `--emit=llvm-ir` can capture them.

use clust::messages::{
    ClaudeModel,
    MaxTokens,
    Message,
    MessagesRequestBody,
    MessagesResponseBody,
    StreamOption,
};
use clust::{
    ApiKey,
    Client,
};

fn request_body(prompt: &str, streaming: bool) -> MessagesRequestBody {
    let model = ClaudeModel::Claude3Sonnet20240229;
    let max_tokens = MaxTokens::new(1024, model).unwrap();

    MessagesRequestBody {
        model,
        messages: vec![Message::user(prompt)],
        max_tokens,
        stream: if streaming {
            Some(StreamOption::ReturnStream)
        } else {
            None
        },
        ..Default::default()
    }
}

pub async fn send_message(prompt: &str) -> MessagesResponseBody {
    let client = Client::from_api_key(ApiKey::new("dummy-api-key"));
    client
        .create_a_message(request_body(prompt, false))
        .await
        .unwrap()
}

pub async fn stream_message(prompt: &str) {
    let client = Client::from_api_key(ApiKey::new("dummy-api-key"));
    let _stream = client
        .create_a_message_stream(request_body(prompt, true))
        .await
        .unwrap();
}
