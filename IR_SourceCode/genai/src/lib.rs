//! Scratch crate for verifying the compiled ABI shape of `genai::Client`'s
//! chat-sending methods against real LLVM IR. Compiled for real with
//! `cargo rustc --lib -- --emit=llvm-ir -C debuginfo=0` against genai 0.3.5
//! (pinned via rust-toolchain.toml to rustc 1.86.0 / LLVM 19.1.7, matching
//! this repo's llvm-ir/llvm-sys deps). See `LLM_API_IR_VERIFICATION.md` at
//! the repo root for the methodology; mirrors the style of
//! `examples/src/ac_demo_llvm/my_app.rs`. Needs to typecheck/compile, not
//! run correctly.

use genai::chat::{ChatMessage, ChatOptions, ChatRequest, ChatResponse, ChatStreamResponse};
use genai::{Client, Result};

pub async fn send_chat(client: &Client, model: &str) -> Result<ChatResponse> {
    let request = ChatRequest::new(vec![ChatMessage::user("hello")]);
    client.exec_chat(model, request, None).await
}

pub async fn send_chat_with_options(
    client: &Client,
    model: &str,
    options: &ChatOptions,
) -> Result<ChatResponse> {
    let request = ChatRequest::new(vec![
        ChatMessage::system("you are a helpful assistant"),
        ChatMessage::user("hello"),
    ]);
    client.exec_chat(model, request, Some(options)).await
}

pub async fn send_chat_stream(client: &Client, model: &str) -> Result<ChatStreamResponse> {
    let request = ChatRequest::new(vec![ChatMessage::user("hello, streamed")]);
    client.exec_chat_stream(model, request, None).await
}

pub async fn default_client_send_chat() -> Result<ChatResponse> {
    let client = Client::default();
    let request = ChatRequest::from_user("hello from default client");
    client.exec_chat("gpt-4o-mini", request, None).await
}

/// Plain (non-async) wrappers that drive the above futures to completion via
/// a real executor. Debug-mode `--emit=llvm-ir` only codegens a bare
/// coroutine constructor for a `pub async fn` that's never actually polled
/// anywhere reachable in this crate -- the real call to
/// `genai::Client::exec_chat`/`exec_chat_stream` lives inside the generated
/// `Future::poll` body, which only gets monomorphized (and thus shows up in
/// the emitted IR as a `declare` for the real extern symbol) if something
/// non-generic in this crate actually polls it. `Runtime::block_on` is a
/// generic fn instantiated here with our concrete future type, which forces
/// exactly that.
pub fn force_codegen_exec_chat(client: &Client, model: &str) -> Result<ChatResponse> {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(send_chat(client, model))
}

pub fn force_codegen_exec_chat_stream(client: &Client, model: &str) -> Result<ChatStreamResponse> {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(send_chat_stream(client, model))
}
