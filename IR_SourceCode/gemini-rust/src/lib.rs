//! Scratch crate to compile real code against `gemini-rust` 2.0.0 and inspect
//! the resulting LLVM IR, verifying `datasets/llm_api_functions.json`'s
//! `gemini-rust` entries against a real compiled ABI shape rather than
//! documentation. See `LLM_API_IR_VERIFICATION.md` at the repo root for the
//! full methodology. Mirrors the style of
//! `examples/src/ac_demo_llvm/my_app.rs`: plain functions calling the
//! catalogued methods with plausible (not necessarily runnable) arguments,
//! compiled in debug mode so the calls aren't inlined away.

use gemini_rust::Gemini;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Waker};

/// `Gemini::generate_content` -- not itself async, returns a `ContentBuilder`
/// synchronously. Deprecated since 1.8.0 in favor of `create_interaction()`,
/// but still present and callable in 2.0.0.
#[allow(deprecated)]
pub fn build_content_request(client: &Gemini) -> gemini_rust::ContentBuilder {
    client.generate_content()
}

/// `ContentBuilder::execute` -- async, consumes `self`, returns
/// `Result<GenerationResponse, ClientError>`.
#[allow(deprecated)]
pub async fn send_generate_content(
    client: &Gemini,
) -> Result<gemini_rust::GenerationResponse, gemini_rust::ClientError> {
    client
        .generate_content()
        .with_system_prompt("You are a helpful assistant.")
        .with_user_message("Hello, Gemini!")
        .execute()
        .await
}

/// `ContentBuilder::execute_stream` -- async, consumes `self`, returns
/// `Result<GenerationStream, ClientError>`.
#[allow(deprecated)]
pub async fn stream_generate_content(
    client: &Gemini,
) -> Result<gemini_rust::GenerationStream, gemini_rust::ClientError> {
    client
        .generate_content()
        .with_user_message("Hello, Gemini!")
        .execute_stream()
        .await
}

/// Constructs a client with a dummy API key -- fine, since this crate only
/// needs to typecheck/compile, not run correctly.
pub fn make_client() -> Gemini {
    Gemini::new("dummy-key").expect("dummy client construction")
}

/// `async fn` bodies are lazy: nothing in `send_generate_content`/
/// `stream_generate_content` -- not even the code before their first
/// `.await` -- actually runs (or gets codegen'd into IR) unless something
/// polls the returned future at least once. These plain (non-async) driver
/// functions force exactly that: they poll each future one time with a
/// no-op waker, purely so the monomorphization collector treats the
/// coroutine's `poll` body (which is where `ContentBuilder::execute`/
/// `execute_stream` actually get called) as reachable and emits it into the
/// `.ll` output. Getting `Poll::Pending` back (since there's no real
/// executor/network here) is expected and fine -- this never needs to run,
/// only to compile.
pub fn drive_send_generate_content(client: &Gemini) {
    let fut = send_generate_content(client);
    let mut fut = pin!(fut);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let _ = fut.as_mut().poll(&mut cx);
}

pub fn drive_stream_generate_content(client: &Gemini) {
    let fut = stream_generate_content(client);
    let mut fut = pin!(fut);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let _ = fut.as_mut().poll(&mut cx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_typechecks() {
        let _ = make_client;
        let _ = build_content_request;
        let _ = send_generate_content;
        let _ = stream_generate_content;
        let _ = drive_send_generate_content;
        let _ = drive_stream_generate_content;
    }
}
