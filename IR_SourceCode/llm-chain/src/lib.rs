//! Scratch crate used solely to compile real calls against the real
//! `llm-chain` / `llm-chain-openai` crates and inspect the emitted LLVM IR
//! for `datasets/llm_api_functions.json`'s "llm-chain" entries. See
//! `LLM_API_IR_VERIFICATION.md` at the repo root for the methodology.
//!
//! `llm_chain_openai` is pulled in as a dependency purely to get a
//! concrete `Executor` impl (`llm_chain_openai::chatgpt::Executor`) to
//! monomorphize `llm_chain::traits::Executor::execute` against -- the
//! trait itself is `#[async_trait]`-boxed and not `dyn`-compatible, so
//! there's no way to observe its real ABI shape without picking one
//! concrete backend.
//!
//! Both wrapper functions below are deliberately **plain (non-`async`)
//! fns that call-but-don't-`.await`** the target method, returning the
//! resulting `impl Future` value as-is. Mirrors the reqwest::send()
//! wrapper style described in `LLM_API_IR_VERIFICATION.md`'s "no sret at
//! all" section: wrapping the call in another `async fn` of our own would
//! bury the real call inside *our* generated coroutine's `poll()` body,
//! which (per this repo's already-committed `async-openai`/`clust`
//! scratch crates) never gets codegenned for a never-actually-driven
//! `pub async fn` -- only the outer "build the coroutine env" shell does.
//! Calling-without-awaiting from an ordinary fn instead makes the real
//! callee call/declare show up directly in *this* function's body, which
//! is what the JSON's `verified_via` quotes were pulled from.

use std::future::Future;

use llm_chain::chains::sequential::{Chain, SequentialChainError};
use llm_chain::options::Options;
use llm_chain::output::Output;
use llm_chain::prompt::Prompt;
use llm_chain::traits::{Executor, ExecutorError};
use llm_chain::Parameters;
use llm_chain_openai::chatgpt::Executor as ChatGptExecutor;

/// Calls `llm_chain::traits::Executor::execute` through the concrete
/// `llm_chain_openai::chatgpt::Executor` backend. Real IR (per
/// `LLM_API_IR_VERIFICATION.md`) shows this returns a register-pair fat
/// pointer `{ ptr, ptr }` -- the `#[async_trait]`-boxed
/// `Pin<Box<dyn Future<...> + Send>>` -- with NO leading `sret` slot,
/// despite the trait's Rust-level signature returning `Result<Output,
/// ExecutorError>`.
pub fn call_execute<'a>(
    exec: &'a ChatGptExecutor,
    options: &'a Options,
    prompt: &'a Prompt,
) -> impl Future<Output = Result<Output, ExecutorError>> + Send + 'a {
    exec.execute(options, prompt)
}

/// Calls `llm_chain::chains::sequential::Chain::run`. Unlike
/// `Executor::execute` above, this is a plain (non-`async_trait`) generic
/// `async fn`, so real IR shows it DOES get an ordinary leading `sret`
/// slot for its compiler-generated coroutine state machine.
pub fn call_chain_run<'a>(
    chain: &'a Chain,
    parameters: Parameters,
    executor: &'a ChatGptExecutor,
) -> impl Future<Output = Result<Output, SequentialChainError>> + 'a {
    chain.run(parameters, executor)
}

/// Builds a concrete `llm_chain_openai::chatgpt::Executor` -- used to
/// give the two wrapper functions above a real, plausible call site
/// elsewhere in the catalogue's verification tooling if needed. Not
/// itself a catalogued entry.
pub fn make_executor() -> Result<ChatGptExecutor, llm_chain::traits::ExecutorCreationError> {
    ChatGptExecutor::new()
}
