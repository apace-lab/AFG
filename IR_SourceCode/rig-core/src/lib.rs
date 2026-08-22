//! Scratch crate used to compile real code against `rig-core` and inspect
//! the generated LLVM IR for two catalogued entries in
//! `datasets/llm_api_functions.json`:
//!
//! - `rig::completion::request::Prompt::prompt` -- called via method syntax
//!   on an `Agent<M>` built from an `openai::Client`.
//! - `rig::completion::request::CompletionModel::completion` -- called
//!   directly on `rig::providers::openai::responses_api::ResponsesCompletionModel`
//!   (the concrete type `openai::Client::completion_model` returns in this
//!   version of the crate).
//!
//! Pinned to rig-core **0.16.0** (see `../../LLM_API_IR_VERIFICATION.md` --
//! every release from 0.17.1 through 0.41.0 uses let-chains internally,
//! which needs rustc >= 1.88 to parse, incompatible with this repo's
//! LLVM-19-pinned rustc 1.86.0). Only needs to typecheck/compile, not run
//! correctly -- uses a dummy API key string. Mirrors the style of
//! `examples/src/ac_demo_llvm/my_app.rs`.
//!
//! Both `Prompt::prompt` and `CompletionModel::completion` are lazy: as
//! with any `async fn`/future-returning method, nothing in their body
//! actually runs -- and nothing gets monomorphized into this crate's
//! object code -- until something drives the returned future. A bare
//! `pub async fn` wrapper that just does `foo().await` and returns is
//! *itself* lazy the same way (calling it only builds a coroutine; the
//! coroutine's `poll`/resume body, which is where the real call to
//! `Prompt::prompt`/`CompletionModel::completion` lives, is only
//! monomorphized if something reachable from this crate's own compilation
//! actually polls it). Since this scratch crate has no consumer, these
//! wrappers are plain (non-`async`) functions that force the future with
//! `futures::executor::block_on` so the whole call chain is eagerly
//! collected and shows up in the emitted `.ll`.

use futures::executor::block_on;
use rig::client::CompletionClient;
use rig::completion::request::{CompletionModel, Prompt};
use rig::providers::openai;
use std::future::IntoFuture;

/// Exercises `Prompt::prompt`, called via method syntax on an `Agent<M>`.
pub fn ask_agent(question: &str) -> Result<String, rig::completion::PromptError> {
    let client = openai::Client::new("dummy-api-key");
    let agent = client.agent("gpt-4").build();
    block_on(agent.prompt(question).into_future())
}

/// Exercises `CompletionModel::completion`, called directly on the concrete
/// `ResponsesCompletionModel` that `Client::completion_model` returns.
pub fn ask_completion_model(
    prompt: &str,
) -> Result<
    rig::completion::request::CompletionResponse<
        <openai::responses_api::ResponsesCompletionModel as CompletionModel>::Response,
    >,
    rig::completion::CompletionError,
> {
    let client = openai::Client::new("dummy-api-key");
    let model: openai::responses_api::ResponsesCompletionModel = client.completion_model("gpt-4");
    let request = model.completion_request(prompt).build();
    block_on(model.completion(request))
}
