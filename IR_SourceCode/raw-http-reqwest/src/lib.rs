//! Scratch crate used solely to compile real calls against the real
//! `reqwest` crate and inspect the emitted LLVM IR for
//! `datasets/llm_api_functions.json`'s "raw-http-reqwest" entries. See
//! `LLM_API_IR_VERIFICATION.md` at the repo root for the methodology.
//!
//! Mirrors the style of `examples/src/ac_demo_llvm/my_app.rs`: plain
//! functions that call the catalogued SDK methods with plausible (not
//! necessarily runnable) arguments, compiled in debug mode so the calls
//! aren't inlined away before `--emit=llvm-ir` can capture them.
//!
//! Covers two entries, both named `RequestBuilder::send` but on different
//! types with opposite ABI shapes (see "Two 'no sret at all' surprises" in
//! `LLM_API_IR_VERIFICATION.md`):
//!   - `reqwest::RequestBuilder::send` (async) -- a plain fn returning
//!     `impl Future<Output = Result<Response, Error>>`, not an `async fn`
//!     itself. The concrete future is small (16 bytes), so it's returned
//!     in a register pair, no `sret`.
//!   - `reqwest::blocking::RequestBuilder::send` -- genuinely synchronous,
//!     really does return `Result<Response, Error>` directly, which is
//!     large enough (176 bytes) to be `sret`-returned.

use std::future::Future;

pub async fn do_send() {
    let client = reqwest::Client::new();
    let _ = client.get("http://example.com").send().await;
}

pub fn do_blocking_send() {
    let client = reqwest::blocking::Client::new();
    let _ = client.get("http://example.com").send();
}

// `do_send`'s own generated function body only *constructs* the coroutine
// (async fn semantics: calling it doesn't run any of the body -- that
// happens on first `.poll()`). rustc's mono-item collector won't emit the
// coroutine's `poll` body (where the real `.send()` call site lives)
// unless something in this crate actually polls it. Drive it once here so
// that call site shows up in the emitted IR.
pub fn drive_do_send_once() {
    let mut fut = std::pin::pin!(do_send());
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let _ = fut.as_mut().poll(&mut cx);
}
