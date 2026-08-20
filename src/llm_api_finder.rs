use crate::provider_hints::find_provider_hint;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub library: String,
    pub fn_name: String,
    /// "llm-api-prompt" (building/assembling the request that will be sent --
    /// message/content builders, request builders) | "llm-api-chat" (the
    /// outbound call that actually sends the assembled request to the LLM
    /// service) | "unspecified" (missing from the catalog entry -- predates
    /// this split; treat as "llm-api-chat", every such entry is that kind).
    pub category: String,
    pub return_type: String,
    pub parameter_type: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub func_id: String,
    pub function: String,
    pub basic_block: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMatch {
    pub library: String,
    pub fn_name: String,
    /// Copied from the matching `Signature::category` -- see its doc comment.
    pub category: String,
    pub match_strategy: String,
    pub callsite: CallSite,
    pub raw_line: String,
    /// Best-effort provider guess for `raw-http-reqwest` matches, derived from
    /// REST path suffixes seen in string literals earlier in the same
    /// function (see `find_provider_hint`). `None` when no known suffix was
    /// found, or for matches from libraries whose name already identifies
    /// the provider/SDK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load all LLM API signatures from `datasets_path/llm_api_functions.json`.
/// Re-parsed on every call so users can update the file without recompiling.
pub fn load_signatures(datasets_path: &Path) -> Result<Vec<Signature>, Box<dyn std::error::Error>> {
    let json_path = datasets_path.join("llm_api_functions.json");
    let content = fs::read_to_string(&json_path)
        .map_err(|e| format!("cannot read {}: {}", json_path.display(), e))?;
    let data: HashMap<String, serde_json::Value> = serde_json::from_str(&content)?;

    let mut sigs = Vec::new();
    for (lib_name, entries) in &data {
        if lib_name.starts_with('_') {
            continue;
        }
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for entry in entries {
            let fn_name = entry["fn_name"].as_str().unwrap_or("").to_string();
            if fn_name.is_empty() {
                continue;
            }
            let category = entry
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified")
                .to_string();
            let return_type = entry
                .get("return_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let parameter_type = entry
                .get("parameter_type")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            sigs.push(Signature {
                library: lib_name.clone(),
                fn_name,
                category,
                return_type,
                parameter_type,
            });
        }
    }
    Ok(sigs)
}

// ── Matching ──────────────────────────────────────────────────────────────────

struct Matcher {
    strategy: &'static str,
    pattern: Regex,
}

/// Build per-signature regex matchers (same three strategies as the Python tool).
fn make_matchers(sig: &Signature) -> Vec<Matcher> {
    let parts: Vec<&str> = sig.fn_name.split("::").collect();
    let method = parts.last().copied().unwrap_or("");
    let struct_path = if parts.len() > 1 {
        parts[..parts.len() - 1].join("::")
    } else {
        String::new()
    };

    let mut matchers = Vec::new();

    // 1. Direct:  async_openai::chat::Chat::create<...>(
    let direct_pat = format!(
        r"{}(?:<[^(]*)?\s*\(",
        regex::escape(&sig.fn_name)
    );
    if let Ok(re) = Regex::new(&direct_pat) {
        matchers.push(Matcher { strategy: "direct", pattern: re });
    }

    // 2. Angle-bracket:  <async_openai::chat::Chat ...>::create<...>(
    if !struct_path.is_empty() {
        let ab_pat = format!(
            r"<\s*{}[^>]*>\s*::\s*{}(?:<[^(]*)?\s*\(",
            regex::escape(&struct_path),
            regex::escape(method)
        );
        if let Ok(re) = Regex::new(&ab_pat) {
            matchers.push(Matcher { strategy: "angle-bracket", pattern: re });
        }
    }

    // 3. Short-name:  Chat::create(  (last two path segments — lower confidence)
    if parts.len() >= 2 {
        let last_two = parts[parts.len() - 2..].join("::");
        let short_pat = format!(r"{}\s*\(", regex::escape(&last_two));
        if let Ok(re) = Regex::new(&short_pat) {
            matchers.push(Matcher { strategy: "short-name", pattern: re });
        }
    }

    matchers
}

// ── MIR line patterns ─────────────────────────────────────────────────────────

static RE_FUNC_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\[FuncId\((\d+)\)\s*-\s*"([^"]+)"\]"#).unwrap()
});

static RE_BB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s+(bb\w+):\s*\{").unwrap()
});

// Captures callee: optional "dest = " prefix, then everything up to "("
static RE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s+(?:_\d+\s*=\s*)?(?P<callee>[^=(][^(]*)\(").unwrap()
});

// Captures every quoted string literal on a line, e.g. `const "..."` or a
// format-string argument to `alloc::fmt::format`.
static RE_STRING_LIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap()
});

// ── Scanner ───────────────────────────────────────────────────────────────────

/// Remove `::<...>` turbofish segments from a callee path, including nested
/// generics (e.g. `Chat::<'_, mycrate::config::OpenAIConfig>::create` ->
/// `Chat::create`). MIR pretty-printing places generic args mid-path on the
/// receiver type, which the fixed-string/last-two-segment matchers below
/// don't expect between path separators.
fn strip_turbofish(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ':' && chars.get(i + 1) == Some(&':') && chars.get(i + 2) == Some(&'<') {
            let mut depth = 1;
            let mut j = i + 3;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '<' => depth += 1,
                    '>' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            i = j;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Scan `mir_content` for calls matching any of `sigs`.
/// Returns one `ApiMatch` per unique (callsite, signature) pair found.
pub fn scan_mir(mir_content: &str, sigs: &[Signature]) -> Vec<ApiMatch> {
    let sig_matchers: Vec<(&Signature, Vec<Matcher>)> = sigs
        .iter()
        .map(|sig| (sig, make_matchers(sig)))
        .collect();

    let mut matches = Vec::new();
    let mut current_func_id = String::from("unknown");
    let mut current_func_name = String::from("unknown");
    let mut current_bb = String::from("unknown");
    // String literals seen so far in the current function, oldest first —
    // feeds find_provider_hint for raw-http-reqwest matches. Reset whenever
    // we enter a new function.
    let mut func_string_literals: Vec<String> = Vec::new();

    for (lineno, line) in mir_content.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        if let Some(caps) = RE_FUNC_HEADER.captures(line) {
            current_func_id = format!("FuncId({})", &caps[1]);
            current_func_name = caps[2].to_string();
            current_bb = String::from("unknown");
            func_string_literals.clear();
            continue;
        }
        if let Some(caps) = RE_BB.captures(line) {
            current_bb = caps[1].to_string();
            continue;
        }
        for lit in RE_STRING_LIT.captures_iter(line) {
            func_string_literals.push(lit[1].to_string());
        }
        let Some(caps) = RE_CALL.captures(line) else {
            continue;
        };

        // Re-append "(" so that patterns ending with \( can match
        let callee_raw = format!("{}(", caps["callee"].trim());
        let callee_raw = strip_turbofish(&callee_raw);

        'sig: for (sig, matchers) in &sig_matchers {
            for matcher in matchers {
                if matcher.pattern.is_match(&callee_raw) {
                    let provider_hint = if sig.library == "raw-http-reqwest" {
                        find_provider_hint(&func_string_literals)
                    } else {
                        None
                    };
                    matches.push(ApiMatch {
                        library: sig.library.clone(),
                        fn_name: sig.fn_name.clone(),
                        category: sig.category.clone(),
                        match_strategy: matcher.strategy.to_string(),
                        callsite: CallSite {
                            func_id: current_func_id.clone(),
                            function: current_func_name.clone(),
                            basic_block: current_bb.clone(),
                            line: lineno,
                        },
                        raw_line: line.trim().to_string(),
                        provider_hint,
                    });
                    break 'sig;
                }
            }
        }
    }

    matches
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures: real rupta MIR output from various demo projects ───────────

    // async-openai via turbofish (1 call site): tabby chat-harness MIR.
    // async_openai_alt::Chat::<'_, OpenAIConfig>::create — exercises short-name
    // matching after turbofish stripping.
    const TEST_TARGET_MIR: &str =
        include_str!("../examples/tabby_direct_mir.txt");

    // demo MIR: async-openai (stub) + raw-http-reqwest (blocking client)
    const DEMO_MIR: &str =
        include_str!("../examples/demo_mir.txt");

    // genai MIR: genai::Client::exec_chat (direct match, no other SDK calls)
    const GENAI_DEMO_MIR: &str =
        include_str!("../examples/genai_mir.txt");

    fn datasets_path() -> &'static Path {
        Box::leak(Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").into_boxed_path())
    }

    // ── Helper: build a minimal Signature for inline MIR tests ───────────────

    fn sig(library: &str, fn_name: &str) -> Signature {
        Signature {
            library: library.to_string(),
            fn_name: fn_name.to_string(),
            category: "llm-api-chat".to_string(),
            return_type: String::new(),
            parameter_type: vec![],
        }
    }

    // ── Loader test ───────────────────────────────────────────────────────────

    #[test]
    fn loads_all_sdk_signatures() {
        let sigs = load_signatures(datasets_path()).expect("load_signatures failed");
        assert!(!sigs.is_empty(), "expected at least one signature");

        // All documented libraries must appear
        let libs: Vec<_> = sigs.iter().map(|s| s.library.as_str()).collect();
        for expected in &[
            "async-openai",
            "ollama-rs",
            "clust",
            "rig-core",
            "gemini-rust",
            "anthropic-sdk",
            "misanthropic",
            "llm-chain",
            "genai",
            "raw-http-reqwest",
        ] {
            assert!(
                libs.contains(expected),
                "library '{expected}' missing from loaded signatures"
            );
        }
    }

    // ── async-openai: fixture-based test ──────────────────────────────────────

    #[test]
    fn detects_async_openai_from_fixture() {
        let sigs = load_signatures(datasets_path()).expect("load_signatures failed");
        let matches = scan_mir(TEST_TARGET_MIR, &sigs);

        let openai_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.library == "async-openai")
            .collect();

        // The tabby fixture has one Chat::create call emitted as
        // async_openai_alt::Chat::<'_, OpenAIConfig>::create — the turbofish
        // is stripped and short-name fires.
        assert_eq!(
            openai_matches.len(),
            1,
            "expected 1 async-openai match, got: {:#?}",
            openai_matches
        );
        assert_eq!(openai_matches[0].fn_name, "async_openai::chat::Chat::create");
        assert_eq!(openai_matches[0].match_strategy, "short-name");
    }

    // ── ollama-rs: inline MIR snippet ─────────────────────────────────────────

    #[test]
    fn detects_ollama_rs() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_ollama"]
fn run_ollama() -> () {
    let _0: ();
    let _1: ollama_rs::Ollama;
    let _2: std::result::Result<(), ()>;

    bb0: {
        _2 = ollama_rs::Ollama::generate(move _1, const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
[FuncId(2) - "my_app::run_ollama_chat"]
fn run_ollama_chat() -> () {
    let _0: ();
    let _1: ollama_rs::Ollama;
    let _2: std::result::Result<(), ()>;

    bb0: {
        _2 = ollama_rs::Ollama::send_chat_messages(move _1, const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![
            sig("ollama-rs", "ollama_rs::Ollama::generate"),
            sig("ollama-rs", "ollama_rs::Ollama::send_chat_messages"),
        ];
        let matches = scan_mir(MIR, &sigs);
        let fns: Vec<_> = matches.iter().map(|m| m.fn_name.as_str()).collect();
        assert!(fns.contains(&"ollama_rs::Ollama::generate"), "missed generate");
        assert!(
            fns.contains(&"ollama_rs::Ollama::send_chat_messages"),
            "missed send_chat_messages"
        );
    }

    // ── gemini-rust: inline MIR snippet ──────────────────────────────────────

    #[test]
    fn detects_gemini_rust() {
        // Names below match the real gemini-rust API (2026-08 IR-verification
        // pass, see LLM_API_IR_VERIFICATION.md) -- the crate's actual builder
        // type is `ContentBuilder`, not `GenerateContentBuilder`; there is no
        // `Conversation` type or `send_message` method anywhere in the crate.
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_gemini"]
fn run_gemini() -> () {
    let _0: ();
    let _1: gemini_rust::Gemini;
    let _2: gemini_rust::ContentBuilder;
    let _3: std::result::Result<gemini_rust::GenerationResponse, gemini_rust::ClientError>;

    bb0: {
        _2 = gemini_rust::Gemini::generate_content(move _1) -> [return: bb1, unwind continue];
    }
    bb1: {
        _3 = gemini_rust::ContentBuilder::execute(move _2) -> [return: bb2, unwind continue];
    }
    bb2: { return; }
}
[FuncId(2) - "my_app::run_gemini_stream"]
fn run_gemini_stream() -> () {
    let _0: ();
    let _1: gemini_rust::ContentBuilder;
    let _2: std::result::Result<gemini_rust::GenerationStream, gemini_rust::ClientError>;

    bb0: {
        _2 = gemini_rust::ContentBuilder::execute_stream(move _1) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![
            sig("gemini-rust", "gemini_rust::Gemini::generate_content"),
            sig("gemini-rust", "gemini_rust::ContentBuilder::execute"),
            sig("gemini-rust", "gemini_rust::ContentBuilder::execute_stream"),
        ];
        let matches = scan_mir(MIR, &sigs);
        let fns: Vec<_> = matches.iter().map(|m| m.fn_name.as_str()).collect();
        assert!(fns.contains(&"gemini_rust::Gemini::generate_content"), "missed generate_content");
        assert!(
            fns.contains(&"gemini_rust::ContentBuilder::execute"),
            "missed execute"
        );
        assert!(
            fns.contains(&"gemini_rust::ContentBuilder::execute_stream"),
            "missed execute_stream"
        );
    }

    // ── anthropic-sdk: inline MIR snippet ────────────────────────────────────

    #[test]
    fn detects_anthropic_sdk() {
        // Builder-chain shape: Client::new(key).messages().model(...).build()?
        // then .execute(callback). Only the final Request::execute call is
        // what the signature matches against.
        // anthropic_sdk has no dedicated error type -- it uses anyhow::Error
        // throughout (2026-08 IR-verification pass corrected the prior guess
        // of `anthropic_sdk::AnthropicError`, which doesn't exist).
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_anthropic"]
fn run_anthropic() -> () {
    let _0: ();
    let _1: anthropic_sdk::RequestBuilder;
    let _2: std::result::Result<anthropic_sdk::Request, anyhow::Error>;
    let _3: anthropic_sdk::Request;
    let _4: std::result::Result<(), anyhow::Error>;

    bb0: {
        _2 = anthropic_sdk::RequestBuilder::build(move _1) -> [return: bb1, unwind continue];
    }
    bb1: {
        _4 = anthropic_sdk::Request::execute(move _3, move _5) -> [return: bb2, unwind continue];
    }
    bb2: { return; }
}
"#;
        let sigs = vec![sig("anthropic-sdk", "anthropic_sdk::Request::execute")];
        let matches = scan_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1, "missed anthropic_sdk::Request::execute");
        assert_eq!(matches[0].match_strategy, "direct");
    }

    // ── clust: inline MIR snippet ─────────────────────────────────────────────

    #[test]
    fn detects_clust() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_clust"]
fn run_clust() -> () {
    let _0: ();
    let _1: clust::Client;
    let _2: clust::messages::MessagesRequestBody;
    let _3: std::result::Result<(), ()>;

    bb0: {
        _3 = clust::Client::create_a_message(move _1, move _2) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("clust", "clust::Client::create_a_message")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed clust::Client::create_a_message");
    }

    #[test]
    fn detects_clust_stream() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_clust_stream"]
fn run_clust_stream() -> () {
    let _0: ();
    let _1: clust::Client;
    let _2: clust::messages::MessagesRequestBody;
    let _3: std::result::Result<clust::messages::MessageChunkStream, clust::ApiError>;

    bb0: {
        _3 = clust::Client::create_a_message_stream(move _1, move _2) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("clust", "clust::Client::create_a_message_stream")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed clust::Client::create_a_message_stream");
    }

    // ── rig-core: inline MIR snippet ──────────────────────────────────────────

    #[test]
    fn detects_rig_core() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_rig_agent"]
fn run_rig_agent() -> () {
    let _0: ();
    let _1: rig::agent::Agent<rig::providers::anthropic::completion::CompletionModel>;
    let _2: std::result::Result<alloc::string::String, rig::completion::PromptError>;

    bb0: {
        _2 = rig::completion::Prompt::prompt(move _1, const "hello") -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("rig-core", "rig::completion::Prompt::prompt")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed rig::completion::Prompt::prompt");
    }

    #[test]
    fn detects_rig_completion_model() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_rig_completion_model"]
fn run_rig_completion_model() -> () {
    let _0: ();
    let _1: rig::providers::anthropic::completion::CompletionModel;
    let _2: rig::completion::CompletionRequest;
    let _3: std::result::Result<rig::completion::CompletionResponse<rig::providers::anthropic::completion::CompletionResponse>, rig::completion::CompletionError>;

    bb0: {
        _3 = rig::completion::CompletionModel::completion(move _1, move _2) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("rig-core", "rig::completion::CompletionModel::completion")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed rig::completion::CompletionModel::completion");
    }

    // ── misanthropic: inline MIR snippet ─────────────────────────────────────

    #[test]
    fn detects_misanthropic() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_misanthropic"]
fn run_misanthropic() -> () {
    let _0: ();
    let _1: misanthropic::Client;
    let _2: std::result::Result<(), ()>;

    bb0: {
        _2 = misanthropic::Client::message(move _1, const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("misanthropic", "misanthropic::Client::message")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed misanthropic::Client::message");
    }

    // ── llm-chain: inline MIR snippet ────────────────────────────────────────

    #[test]
    fn detects_llm_chain() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_chain"]
fn run_chain() -> () {
    let _0: ();
    let _1: llm_chain::traits::Executor;
    let _2: std::result::Result<(), ()>;

    bb0: {
        _2 = llm_chain::traits::Executor::execute(move _1, const (), const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("llm-chain", "llm_chain::traits::Executor::execute")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed llm_chain::traits::Executor::execute");
    }

    // ── genai: inline MIR snippet ─────────────────────────────────────────────

    #[test]
    fn detects_genai() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::run_genai"]
fn run_genai() -> () {
    let _0: ();
    let _1: genai::Client;
    let _2: std::result::Result<(), ()>;

    bb0: {
        _2 = genai::Client::exec_chat(move _1, const "gpt-4", const (), const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("genai", "genai::Client::exec_chat")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed genai::Client::exec_chat");
    }

    // ── raw-http-reqwest: inline MIR snippet ─────────────────────────────────

    #[test]
    fn detects_reqwest() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::call_api_directly"]
fn call_api_directly() -> () {
    let _0: ();
    let _1: reqwest::RequestBuilder;
    let _2: std::result::Result<reqwest::Response, reqwest::Error>;

    bb0: {
        _2 = reqwest::RequestBuilder::send(move _1) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("raw-http-reqwest", "reqwest::RequestBuilder::send")];
        let matches = scan_mir(MIR, &sigs);
        assert!(!matches.is_empty(), "missed reqwest::RequestBuilder::send");
    }

    // ── raw-http-reqwest: provider_hint from a runtime-built URL ─────────────

    #[test]
    fn provider_hint_survives_dynamic_base_url() {
        // Mirrors GitButler's but-llm/src/anthropic.rs: the host is a runtime
        // config value (`api_base`), never a MIR literal, but the format
        // string still carries the literal "/messages" path suffix — that's
        // what find_provider_hint should key on.
        const MIR: &str = r#"
[FuncId(1) - "but_llm::anthropic::send_message"]
fn send_message() -> () {
    let _0: ();
    let _1: alloc::string::String;
    let _2: reqwest::RequestBuilder;
    let _3: std::result::Result<reqwest::Response, reqwest::Error>;

    bb0: {
        _1 = alloc::fmt::format(move _4) -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = reqwest::Client::post::<alloc::string::String>(move _5, move _1) -> [return: bb2, unwind continue];
    }
    bb2: {
        _3 = reqwest::RequestBuilder::send(move _2) -> [return: bb3, unwind continue];
    }
    bb3: { return; }
}
"#;
        // The literal captured from the promoted format-string constant, as
        // rupta would emit it ahead of the `alloc::fmt::format` call.
        const MIR_WITH_LITERAL: &str = r#"
[FuncId(1) - "but_llm::anthropic::send_message"]
fn send_message() -> () {
    let _0: ();

    bb0: {
        _1 = alloc::fmt::format(const "{}/messages") -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = reqwest::Client::post::<alloc::string::String>(move _5, move _1) -> [return: bb2, unwind continue];
    }
    bb2: {
        _3 = reqwest::RequestBuilder::send(move _2) -> [return: bb3, unwind continue];
    }
    bb3: { return; }
}
"#;
        let sigs = vec![sig("raw-http-reqwest", "reqwest::RequestBuilder::send")];

        // Sanity: with no literal at all, no hint should fire.
        let matches = scan_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].provider_hint, None);

        // With the format-string literal present, the Anthropic hint fires
        // even though the host itself is a runtime variable.
        let matches = scan_mir(MIR_WITH_LITERAL, &sigs);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].provider_hint.as_deref(),
            Some("Anthropic (Claude Messages API)")
        );
    }

    // ── raw-http-reqwest blocking: inline MIR snippet ────────────────────────

    #[test]
    fn detects_reqwest_blocking() {
        const MIR: &str = r#"
[FuncId(1) - "my_app::call_api_blocking"]
fn call_api_blocking() -> () {
    let _0: ();
    let _1: reqwest::blocking::RequestBuilder;
    let _2: std::result::Result<reqwest::Response, reqwest::Error>;

    bb0: {
        _2 = reqwest::blocking::RequestBuilder::send(move _1) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("raw-http-reqwest", "reqwest::blocking::RequestBuilder::send")];
        let matches = scan_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1, "missed reqwest::blocking::RequestBuilder::send");
        assert_eq!(matches[0].fn_name, "reqwest::blocking::RequestBuilder::send");
        assert_eq!(matches[0].match_strategy, "direct");
    }

    // ── turbofish on receiver type: real-world generic client (tabby) ────────

    #[test]
    fn detects_call_with_mid_path_turbofish() {
        // Real rupta MIR from analyzing TabbyML/tabby's chat client: the
        // receiver type carries its own generic args between path segments
        // (`Chat::<'_, OpenAIConfig>::create`), which no plain fixed-string
        // or last-two-segment match would find without stripping them first.
        const MIR: &str = r#"
[FuncId(1) - "chat_harness::main"]
fn main() -> () {
    let _0: ();
    let _7: async_openai_alt::Chat<'_, async_openai_alt::config::OpenAIConfig>;

    bb0: {
        _7 = async_openai_alt::Chat::<'_, async_openai_alt::config::OpenAIConfig>::create(move _8, move _10) -> [return: bb1, unwind: bb18];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("async-openai", "async_openai::chat::Chat::create")];
        let matches = scan_mir(MIR, &sigs);
        assert_eq!(
            matches.len(),
            1,
            "missed Chat::<...>::create with mid-path turbofish generics"
        );
        assert_eq!(matches[0].match_strategy, "short-name");
    }

    #[test]
    fn strip_turbofish_handles_nested_generics() {
        assert_eq!(
            strip_turbofish("Chat::<'_, mycrate::config::OpenAIConfig>::create("),
            "Chat::create("
        );
        assert_eq!(
            strip_turbofish("alloc::boxed::Box::<T>::new(move _1)"),
            "alloc::boxed::Box::new(move _1)"
        );
        assert_eq!(
            strip_turbofish("std::collections::HashMap::<String, Vec<u8>>::new()"),
            "std::collections::HashMap::new()"
        );
        assert_eq!(strip_turbofish("plain::path::call("), "plain::path::call(");
    }

    // ── full load + scan round-trip on fixture ────────────────────────────────

    #[test]
    fn full_roundtrip_fixture() {
        let sigs = load_signatures(datasets_path()).expect("load_signatures");
        let matches = scan_mir(TEST_TARGET_MIR, &sigs);
        // The tabby fixture contains only async-openai calls; every match must
        // be attributed to "async-openai".
        assert!(!matches.is_empty());
        for m in &matches {
            assert_eq!(
                m.library, "async-openai",
                "unexpected library: {}",
                m.library
            );
        }
    }

    // ── Match-strategy smoke tests ────────────────────────────────────────────

    #[test]
    fn short_name_strategy_fires_for_stub_crate_names() {
        // Stubs expose different crate names (e.g. async_openai_stub) but
        // share the same struct/method names — short-name should still match.
        const MIR: &str = r#"
[FuncId(1) - "test_target::call_chat"]
fn call_chat() -> () {
    let _0: ();
    let _1: async_openai_stub::chat::Chat;

    bb0: {
        _2 = async_openai_stub::chat::Chat::create(_1, const ()) -> [return: bb1, unwind continue];
    }
    bb1: { return; }
}
"#;
        let sigs = vec![sig("async-openai", "async_openai::chat::Chat::create")];
        let matches = scan_mir(MIR, &sigs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].match_strategy, "short-name");
    }

    // ── demo: async-openai + raw-http-reqwest (fixture) ─────────────────────

    #[test]
    fn detects_async_openai_and_reqwest_in_demo() {
        let sigs = load_signatures(datasets_path()).expect("load_signatures");
        let matches = scan_mir(DEMO_MIR, &sigs);

        let libs: Vec<_> = matches.iter().map(|m| m.library.as_str()).collect();
        for expected in &["async-openai", "raw-http-reqwest"] {
            assert!(
                libs.contains(expected),
                "library '{expected}' not found in demo MIR; matches: {:#?}",
                matches
            );
        }

        // async-openai: call_chatgpt_api via stub short-name match
        let openai: Vec<_> = matches.iter().filter(|m| m.library == "async-openai").collect();
        assert!(!openai.is_empty());

        // raw-http-reqwest: call_openai_direct via reqwest::blocking::RequestBuilder::send
        let reqwest: Vec<_> = matches.iter().filter(|m| m.library == "raw-http-reqwest").collect();
        assert_eq!(reqwest.len(), 1);
        assert_eq!(reqwest[0].fn_name, "reqwest::RequestBuilder::send");
        assert_eq!(reqwest[0].match_strategy, "short-name");
    }

    // ── genai-demo: genai::Client::exec_chat (fixture) ───────────────────────

    #[test]
    fn detects_genai_exec_chat_in_genai_demo() {
        let sigs = load_signatures(datasets_path()).expect("load_signatures");
        let matches = scan_mir(GENAI_DEMO_MIR, &sigs);

        let genai_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.library == "genai")
            .collect();
        assert_eq!(
            genai_matches.len(),
            1,
            "expected 1 genai match, got: {:#?}",
            genai_matches
        );
        assert_eq!(genai_matches[0].fn_name, "genai::Client::exec_chat");
        // Direct strategy fires because MIR emits the full path
        assert!(
            matches!(genai_matches[0].match_strategy.as_str(), "direct" | "angle-bracket" | "short-name"),
            "unexpected strategy: {}",
            genai_matches[0].match_strategy
        );
        // No false positives from other libraries
        let other: Vec<_> = matches.iter().filter(|m| m.library != "genai").collect();
        assert!(other.is_empty(), "unexpected non-genai matches: {:#?}", other);
    }

    #[test]
    fn no_false_positives_on_unrelated_calls() {
        const MIR: &str = r#"
[FuncId(1) - "demo::main"]
fn main() -> () {
    bb0: {
        _1 = std::collections::HashMap::<String, String>::new() -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = std::sync::Mutex::<HashMap<String, String>>::new(move _3) -> [return: bb2, unwind continue];
    }
    bb2: { return; }
}
"#;
        let sigs = load_signatures(datasets_path()).expect("load_signatures");
        let matches = scan_mir(MIR, &sigs);
        assert!(
            matches.is_empty(),
            "false positives detected: {:#?}",
            matches
        );
    }
}
