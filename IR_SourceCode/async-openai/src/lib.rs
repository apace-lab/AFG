//! Scratch crate used to compile real `async-openai` 0.41.3 code and inspect
//! the resulting LLVM IR, so the ABI-shape claims in
//! `datasets/llm_api_functions.json`'s `"async-openai"` array can be checked
//! against real compiler output instead of documentation. See
//! `LLM_API_IR_VERIFICATION.md` at the repo root for the methodology this
//! reproduces, and `examples/src/ac_demo_llvm/my_app.rs` for the sibling
//! convention this file follows (plain functions that call the real SDK
//! with plausible-but-not-necessarily-runnable arguments, compiled in debug
//! mode with `--emit=llvm-ir` so the compiler can't inline the call away).
//!
//! Regenerate the IR with, from inside this directory:
//! `cargo rustc --lib -- --emit=llvm-ir -C debuginfo=0`
//! then copy the resulting `target/debug/deps/async_openai_ir_scratch-*.ll`
//! to `ir_output.ll`.

use async_openai::types::audio::{
    AudioInput, CreateSpeechRequestArgs, CreateTranscriptionRequestArgs, SpeechModel, Voice,
};
use async_openai::types::InputSource;
use async_openai::types::chat::{
    ChatCompletionRequestMessage, ChatCompletionRequestUserMessageArgs,
    CreateChatCompletionRequestArgs, Prompt,
};
use async_openai::types::completions::CreateCompletionRequestArgs;
use async_openai::types::embeddings::{CreateEmbeddingRequestArgs, EmbeddingInput};
use async_openai::types::images::CreateImageRequestArgs;
use async_openai::Client;

/// `async_openai::types::chat::ChatCompletionRequestUserMessageArgs::content`
/// -- builder setter, returns `&mut Self`.
pub fn build_user_message() -> ChatCompletionRequestUserMessageArgs {
    let mut builder = ChatCompletionRequestUserMessageArgs::default();
    builder.content("What's the weather like today?");
    builder
}

/// `async_openai::types::chat::ChatCompletionRequestUserMessageArgs::build`
/// -- returns `Result<ChatCompletionRequestUserMessage, OpenAIError>`.
pub fn build_user_message_result() -> Result<ChatCompletionRequestMessage, async_openai::error::OpenAIError> {
    let message = ChatCompletionRequestUserMessageArgs::default()
        .content("What's the weather like today?")
        .build()?;
    Ok(ChatCompletionRequestMessage::User(message))
}

/// `async_openai::types::chat::CreateChatCompletionRequestArgs::model`,
/// `::messages`, and `::build`.
pub fn build_chat_request(
    messages: Vec<ChatCompletionRequestMessage>,
) -> Result<async_openai::types::chat::CreateChatCompletionRequest, async_openai::error::OpenAIError>
{
    CreateChatCompletionRequestArgs::default()
        .model("gpt-4o-mini")
        .messages(messages)
        .build()
}

/// `async_openai::chat::Chat::create` -- native `async fn`, so this one
/// should show an `sret` state-machine return slot in the IR.
pub async fn call_chat_create(
    client: &Client<async_openai::config::OpenAIConfig>,
    request: async_openai::types::chat::CreateChatCompletionRequest,
) -> Result<async_openai::types::chat::CreateChatCompletionResponse, async_openai::error::OpenAIError>
{
    client.chat().create(request).await
}

/// `async_openai::chat::Chat::create_stream`.
pub async fn call_chat_create_stream(
    client: &Client<async_openai::config::OpenAIConfig>,
    request: async_openai::types::chat::CreateChatCompletionRequest,
) -> Result<async_openai::types::chat::ChatCompletionResponseStream, async_openai::error::OpenAIError>
{
    client.chat().create_stream(request).await
}

/// `async_openai::completion::Completions::create`.
pub async fn call_completions_create(
    client: &Client<async_openai::config::OpenAIConfig>,
) -> Result<
    async_openai::types::completions::CreateCompletionResponse,
    async_openai::error::OpenAIError,
> {
    let request = CreateCompletionRequestArgs::default()
        .model("gpt-3.5-turbo-instruct")
        .prompt(Prompt::String("Once upon a time".to_string()))
        .build()?;
    client.completions().create(request).await
}

/// `async_openai::completion::Completions::create_stream`.
pub async fn call_completions_create_stream(
    client: &Client<async_openai::config::OpenAIConfig>,
) -> Result<
    async_openai::types::completions::CompletionResponseStream,
    async_openai::error::OpenAIError,
> {
    let request = CreateCompletionRequestArgs::default()
        .model("gpt-3.5-turbo-instruct")
        .prompt(Prompt::String("Once upon a time".to_string()))
        .build()?;
    client.completions().create_stream(request).await
}

/// `async_openai::embedding::Embeddings::create`.
pub async fn call_embeddings_create(
    client: &Client<async_openai::config::OpenAIConfig>,
) -> Result<
    async_openai::types::embeddings::CreateEmbeddingResponse,
    async_openai::error::OpenAIError,
> {
    let request = CreateEmbeddingRequestArgs::default()
        .model("text-embedding-3-small")
        .input(EmbeddingInput::String("hello world".to_string()))
        .build()?;
    client.embeddings().create(request).await
}

/// `async_openai::image::Images::generate` -- real method name as of
/// 0.41.3 is `generate`, not `create`.
pub async fn call_images_generate(
    client: &Client<async_openai::config::OpenAIConfig>,
) -> Result<async_openai::types::images::ImagesResponse, async_openai::error::OpenAIError> {
    let request = CreateImageRequestArgs::default()
        .prompt("a white siamese cat")
        .build()?;
    client.images().generate(request).await
}

/// `async_openai::audio::Speech::create` -- accessed via `client.audio().speech()`,
/// not `Audio::speech()` directly (that only returns the sub-client accessor).
pub async fn call_speech_create(
    client: &Client<async_openai::config::OpenAIConfig>,
) -> Result<async_openai::types::audio::CreateSpeechResponse, async_openai::error::OpenAIError> {
    let request = CreateSpeechRequestArgs::default()
        .input("Today is a wonderful day to build something people love!")
        .model(SpeechModel::Tts1)
        .voice(Voice::Alloy)
        .build()?;
    client.audio().speech().create(request).await
}

/// `async_openai::audio::Transcriptions::create` -- accessed via
/// `client.audio().transcription()`, not `Audio::transcribe()`.
pub async fn call_transcriptions_create(
    client: &Client<async_openai::config::OpenAIConfig>,
) -> Result<
    async_openai::types::audio::CreateTranscriptionResponseJson,
    async_openai::error::OpenAIError,
> {
    let request = CreateTranscriptionRequestArgs::default()
        .file(AudioInput {
            source: InputSource::Path {
                path: std::path::PathBuf::from("audio.mp3"),
            },
        })
        .model("whisper-1")
        .build()?;
    client.audio().transcription().create(request).await
}

/// NOT one of the catalogued functions -- a plain (non-async) driver whose
/// only job is to force the compiler to actually generate code for every
/// `.await` point's `Future::poll` state machine below it. Calling an
/// `async fn` only ever *constructs* a suspended future/coroutine (that's
/// all `call_chat_create` etc. above compile down to on their own -- no
/// call to the real SDK method appears anywhere in *that* symbol, since
/// nothing runs until something polls it); the real call to e.g.
/// `async_openai::chat::Chat::create` only exists inside the generated
/// `poll()` body, and rustc's dead-code/reachability collector doesn't
/// eagerly generate `poll()` for a future that's never actually driven
/// anywhere in the compiled crate graph. `Runtime::block_on` is generic
/// over the future type, so calling it here with a concrete future forces
/// local monomorphization of the whole poll chain, which is what makes the
/// real SDK call sites show up in the emitted `.ll` at all.
pub fn drive_all() {
    let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
    rt.block_on(async {
        let _ = run_all().await;
    });
}

/// Ties the builder helpers together into one plausible end-to-end call, so
/// the whole chain from message-builder through request-builder through the
/// real network-call methods actually gets exercised in one place.
pub async fn run_all() -> Result<(), async_openai::error::OpenAIError> {
    let client = Client::new();

    let message = build_user_message_result()?;
    let chat_request = build_chat_request(vec![message])?;
    let _ = call_chat_create(&client, chat_request.clone()).await;
    let _ = call_chat_create_stream(&client, chat_request).await;
    let _ = call_completions_create(&client).await;
    let _ = call_completions_create_stream(&client).await;
    let _ = call_embeddings_create(&client).await;
    let _ = call_images_generate(&client).await;
    let _ = call_speech_create(&client).await;
    let _ = call_transcriptions_create(&client).await;

    Ok(())
}
