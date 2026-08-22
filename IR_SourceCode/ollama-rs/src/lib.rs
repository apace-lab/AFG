//! Scratch crate used to compile real `ollama-rs` 0.3.6 call sites to LLVM
//! IR, so the ABI shape recorded in `datasets/llm_api_functions.json` for
//! the `"ollama-rs"` entries can be checked against the real compiler
//! output instead of documentation. Mirrors the style of
//! `examples/src/ac_demo_llvm/my_app.rs`: plain functions that just need to
//! typecheck and compile, not actually run correctly.
//!
//! The bodies are driven through `tokio::runtime::Runtime::block_on` from a
//! plain (non-async) `pub fn` rather than left as bare `pub async fn`s.
//! Reason: an un-awaited `async fn`'s body compiles to two pieces -- a
//! trivial "construct the coroutine" function (which is all a `pub async
//! fn` root pulls in on its own) and a separate `Future::poll` state
//! machine holding the actual call sequence. Nothing in this lib ever
//! polls that state machine, so LLVM's reachability-based mono-item
//! collector never emits it or anything it calls -- confirmed empirically
//! by a first pass that emitted only 6 trivial sret-stub functions with no
//! call/invoke sites at all. Wrapping each call in `block_on` gives the
//! collector an actual poll driver reachable from a `pub fn` root, which
//! pulls the real state machine (and therefore the real SDK call) into the
//! emitted IR. This also matches this repo's documented methodology (see
//! `LLM_API_IR_VERIFICATION.md`, which reports the analogous need to wrap
//! `rig-core`/`llm-chain` calls in `futures::executor::block_on` to see
//! their real eventual output type).
//!
//! See `IR_SourceCode/ollama-rs/rust-toolchain.toml` for why this is
//! pinned to rustc 1.86.0 (last release bundling LLVM 19, matching this
//! repo's `llvm-ir`/`llvm-sys` pin), and `LLM_API_IR_VERIFICATION.md` at
//! the repo root for the full methodology.

use ollama_rs::coordinator::Coordinator;
use ollama_rs::generation::chat::request::ChatMessageRequest;
use ollama_rs::generation::chat::ChatMessage;
use ollama_rs::generation::completion::request::GenerationRequest;
use ollama_rs::generation::embeddings::request::GenerateEmbeddingsRequest;
use ollama_rs::Ollama;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

pub fn call_generate() {
    rt().block_on(async {
        let ollama = Ollama::default();
        let request =
            GenerationRequest::new("llama3".to_string(), "Why is the sky blue?".to_string());
        let _ = ollama.generate(request).await;
    });
}

pub fn call_generate_stream() {
    rt().block_on(async {
        let ollama = Ollama::default();
        let request =
            GenerationRequest::new("llama3".to_string(), "Why is the sky blue?".to_string());
        let _ = ollama.generate_stream(request).await;
    });
}

pub fn call_send_chat_messages() {
    rt().block_on(async {
        let ollama = Ollama::default();
        let messages = vec![ChatMessage::user("Why is the sky blue?".to_string())];
        let request = ChatMessageRequest::new("llama3".to_string(), messages);
        let _ = ollama.send_chat_messages(request).await;
    });
}

pub fn call_send_chat_messages_with_history() {
    rt().block_on(async {
        let ollama = Ollama::default();
        let mut history: Vec<ChatMessage> = Vec::new();
        let messages = vec![ChatMessage::user("Why is the sky blue?".to_string())];
        let request = ChatMessageRequest::new("llama3".to_string(), messages);
        let _ = ollama
            .send_chat_messages_with_history(&mut history, request)
            .await;
    });
}

pub fn call_generate_embeddings() {
    rt().block_on(async {
        let ollama = Ollama::default();
        let request =
            GenerateEmbeddingsRequest::new("llama3".to_string(), "Why is the sky blue?".into());
        let _ = ollama.generate_embeddings(request).await;
    });
}

pub fn call_coordinator_chat() {
    rt().block_on(async {
        let ollama = Ollama::default();
        let history: Vec<ChatMessage> = Vec::new();
        let mut coordinator = Coordinator::new(ollama, "llama3".to_string(), history);
        let messages = vec![ChatMessage::user("Why is the sky blue?".to_string())];
        let _ = coordinator.chat(messages).await;
    });
}
