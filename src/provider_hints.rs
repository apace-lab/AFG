//! Shared LLM provider path-hint table, used by both the Rust MIR scanner
//! (`llm_api_finder`) and the JS/TS source scanner (`llm_api_finder_js`) to
//! guess which provider a raw HTTP call is talking to when no SDK name is
//! available to say so directly.

/// Known REST path suffixes that identify an LLM provider even when the base
/// URL is assembled at runtime (e.g. `` `${apiBase}/messages` ``, where
/// `apiBase` is a config/env value and never appears as a single literal —
/// only the path suffix does). Checked longest-first so a more specific
/// pattern (`/chat/completions`) wins over a shorter one that could also
/// match unrelated text.
///
/// This is a heuristic, not a proof: the same path shape is reused by
/// OpenAI-compatible proxies (Ollama, LM Studio, OpenRouter, etc.), so a hit
/// here names the wire protocol, not necessarily the literal upstream host.
pub const PROVIDER_PATH_HINTS: &[(&str, &str)] = &[
    (
        "/chat/completions",
        "OpenAI-compatible endpoint (OpenAI or a compatible proxy: Ollama, LM Studio, OpenRouter, etc.)",
    ),
    ("/v1/embeddings", "OpenAI-compatible endpoint (Embeddings API)"),
    (
        "/v1/completions",
        "OpenAI-compatible endpoint (legacy Completions API)",
    ),
    ("/messages", "Anthropic (Claude Messages API)"),
    (
        ":generateContent",
        "Gemini (Google Generative Language API)",
    ),
    (
        ":streamGenerateContent",
        "Gemini (Google Generative Language API)",
    ),
    ("/api/generate", "Ollama (native API)"),
    ("/api/chat", "Ollama (native API)"),
];

/// Look for a known provider path suffix among a set of nearby string
/// literals. Returns the first (longest-pattern) hit.
pub fn find_provider_hint<S: AsRef<str>>(nearby_literals: &[S]) -> Option<String> {
    PROVIDER_PATH_HINTS
        .iter()
        .find(|(suffix, _)| {
            nearby_literals
                .iter()
                .any(|lit| lit.as_ref().contains(suffix))
        })
        .map(|(_, provider)| provider.to_string())
}
