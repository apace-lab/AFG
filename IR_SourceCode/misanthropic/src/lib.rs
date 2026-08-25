//! Scratch crate used solely to compile real calls against the real
//! `misanthropic` crate (an Anthropic Claude Rust SDK) and inspect the
//! emitted LLVM IR for `datasets/llm_api_functions.json`'s "misanthropic"
//! entries. See `LLM_API_IR_VERIFICATION.md` at the repo root for the
//! methodology.
//!
//! Mirrors the style of `examples/src/ac_demo_llvm/my_app.rs`: plain
//! functions that call the catalogued SDK methods with plausible (not
//! necessarily runnable) arguments, compiled in debug mode so the calls
//! aren't inlined away before `--emit=llvm-ir` can capture them.
//!
//! NOTE: unlike every other scratch crate in `IR_SourceCode/`, this one is
//! pinned to rustc 1.88.0 (see `rust-toolchain.toml`), not this repo's usual
//! 1.86.0. `misanthropic` 1.0.0-alpha.16 uses "let-chain" syntax internally
//! (`if let ... && let ...`), a 2024-edition feature that needs rustc >=1.88
//! to even parse, regardless of what edition this crate declares. That also
//! means the emitted IR here is in LLVM 20.1.x's dialect, not this repo's
//! usual pinned LLVM 19 -- expected and already reflected in the dataset's
//! `verified_via` field for these two entries.

use misanthropic::prompt::message::Role;
use misanthropic::{Client, Prompt};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

// Driven through `block_on` from a plain `pub fn` rather than left as a
// bare `pub async fn` -- see `IR_SourceCode/ollama-rs/src/lib.rs` for why:
// an un-polled async fn's body compiles to a trivial coroutine-constructor
// stub only, with the real call sequence never emitted.
pub fn call_send_message(prompt_text: &str) {
    rt().block_on(async {
        let client = Client::new("dummy-api-key".to_string()).unwrap();

        let prompt = Prompt::default()
            .messages([(Role::User, prompt_text)])
            .unwrap();

        let _ = client.message(&prompt).await.unwrap();
    });
}

pub fn call_stream_message(prompt_text: &str) {
    rt().block_on(async {
        let client = Client::new("dummy-api-key".to_string()).unwrap();

        let prompt = Prompt::default()
            .messages([(Role::User, prompt_text)])
            .unwrap();

        let _ = client.stream(&prompt).await.unwrap();
    });
}
