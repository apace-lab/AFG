//! Shared access-control REST path-hint table, used by both the Rust MIR
//! scanner (`ac_finder`) and the JS/TS source scanner (`ac_finder_js`) to
//! guess which kind of access-control service a raw HTTP call is talking to
//! when no SDK name is available to say so directly. Plays the same role for
//! the AC finder that `provider_hints.rs` plays for the LLM finder, but keyed
//! on authentication/authorization REST conventions (OAuth2, OIDC, OPA,
//! Vault, Keycloak) instead of LLM provider APIs.

/// Known REST path suffixes that identify an access-control service even
/// when the base URL is assembled at runtime (e.g. `` `${authBase}/introspect` ``,
/// where `authBase` is a config/env value and never appears as a single
/// literal — only the path suffix does). Checked in order, so more specific
/// entries (a vendor's exact path shape) are listed before generic ones that
/// could also match inside them (e.g. Keycloak's `/protocol/openid-connect/userinfo`
/// before the bare `/userinfo`).
///
/// This is a heuristic, not a proof: a hit here names the protocol/convention
/// being spoken (e.g. RFC 7662 token introspection), not necessarily which
/// vendor is on the other end of it.
pub const AC_PATH_HINTS: &[(&str, &str)] = &[
    (
        "/.well-known/openid-configuration",
        "OIDC discovery document",
    ),
    (
        "/.well-known/jwks.json",
        "JWKS endpoint (JWT public key retrieval)",
    ),
    (
        "/protocol/openid-connect/token",
        "Keycloak token endpoint",
    ),
    (
        "/protocol/openid-connect/userinfo",
        "Keycloak UserInfo endpoint",
    ),
    ("/oauth/token", "OAuth2 token endpoint (issuance/exchange)"),
    ("/oauth/authorize", "OAuth2/OIDC authorization endpoint"),
    ("/oauth/revoke", "OAuth2 token revocation (RFC 7009)"),
    ("/introspect", "OAuth2 token introspection (RFC 7662)"),
    ("/userinfo", "OIDC UserInfo endpoint"),
    (
        "/v1/data/",
        "Open Policy Agent (OPA) policy decision endpoint",
    ),
    ("/v1/auth/", "HashiCorp Vault auth endpoint"),
];

/// Look for a known access-control path suffix among a set of nearby string
/// literals. Returns the first (most specific, by table order) hit.
pub fn find_ac_hint<S: AsRef<str>>(nearby_literals: &[S]) -> Option<String> {
    AC_PATH_HINTS
        .iter()
        .find(|(suffix, _)| {
            nearby_literals
                .iter()
                .any(|lit| lit.as_ref().contains(suffix))
        })
        .map(|(_, desc)| desc.to_string())
}

/// HTTP header names (lowercase) that carry a credential to an *outbound*
/// request -- the pattern an app uses to authenticate *itself* as a client
/// to a downstream API (an LLM provider, a third-party SDK-less REST API,
/// ...), as opposed to the inbound guards the rest of this catalogue mostly
/// covers. Used by `ac_finder_rs_src`'s `.header("...")` scanner.
pub const AUTH_HEADER_NAMES: &[(&str, &str)] = &[
    (
        "authorization",
        "Authorization header (bearer/basic credential attached to an outbound request)",
    ),
    ("x-api-key", "vendor API key header (e.g. Anthropic, AWS API Gateway)"),
    ("api-key", "vendor API key header (e.g. Azure OpenAI)"),
    ("x-goog-api-key", "Google API key header (e.g. Gemini Developer API)"),
    (
        "ocp-apim-subscription-key",
        "Azure API Management subscription key header",
    ),
];

/// Case-insensitive lookup of `header_name` against `AUTH_HEADER_NAMES`.
pub fn find_auth_header_hint(header_name: &str) -> Option<&'static str> {
    let lower = header_name.to_lowercase();
    AUTH_HEADER_NAMES.iter().find(|(name, _)| *name == lower).map(|(_, desc)| *desc)
}

/// URL query-parameter names (lowercase) that carry a credential to an
/// *outbound* request -- the query-string sibling of `AUTH_HEADER_NAMES`,
/// for APIs that take the credential as `?key=...`/`?access_token=...`
/// rather than a header (most notably the Gemini Developer API's `?key=`).
/// Used by `ac_finder_rs_src`'s `.query("...")` scanner.
///
/// `"key"` on its own is a much more generic word than anything in
/// `AUTH_HEADER_NAMES` (sort keys, cache keys, primary keys, ... routinely
/// show up as a literal query-param name too), so this table trades a higher
/// false-positive rate for catching the single most common real-world case
/// -- same risk/reward call already made for the `token` method name
/// elsewhere in this catalogue (see AC_FINDER.md's Known blind spots).
pub const AUTH_QUERY_PARAM_NAMES: &[(&str, &str)] = &[
    ("key", "Google API key query parameter (e.g. Gemini Developer API)"),
    ("api_key", "vendor API key query parameter"),
    ("apikey", "vendor API key query parameter"),
    ("access_token", "OAuth2 access token query parameter"),
    ("client_secret", "OAuth2 client secret query parameter"),
];

/// Case-insensitive lookup of `param_name` against `AUTH_QUERY_PARAM_NAMES`.
pub fn find_auth_query_param_hint(param_name: &str) -> Option<&'static str> {
    let lower = param_name.to_lowercase();
    AUTH_QUERY_PARAM_NAMES.iter().find(|(name, _)| *name == lower).map(|(_, desc)| *desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_oauth_token_hint() {
        let lits = vec!["https://idp.example.com".to_string(), "/oauth/token".to_string()];
        assert_eq!(
            find_ac_hint(&lits).as_deref(),
            Some("OAuth2 token endpoint (issuance/exchange)")
        );
    }

    #[test]
    fn keycloak_userinfo_wins_over_generic_userinfo() {
        let lits = vec!["/protocol/openid-connect/userinfo".to_string()];
        assert_eq!(
            find_ac_hint(&lits).as_deref(),
            Some("Keycloak UserInfo endpoint")
        );
    }

    #[test]
    fn no_hint_for_unrelated_literal() {
        let lits = vec!["/api/settings".to_string()];
        assert_eq!(find_ac_hint(&lits), None);
    }

    #[test]
    fn finds_auth_header_hint_case_insensitively() {
        assert!(find_auth_header_hint("Authorization").is_some());
        assert!(find_auth_header_hint("X-Api-Key").is_some());
        assert!(find_auth_header_hint("api-key").is_some());
    }

    #[test]
    fn no_auth_header_hint_for_unrelated_header() {
        assert_eq!(find_auth_header_hint("Content-Type"), None);
        assert_eq!(find_auth_header_hint("anthropic-version"), None);
    }

    #[test]
    fn finds_auth_query_param_hint_case_insensitively() {
        assert!(find_auth_query_param_hint("key").is_some());
        assert!(find_auth_query_param_hint("API_KEY").is_some());
        assert!(find_auth_query_param_hint("Access_Token").is_some());
    }

    #[test]
    fn no_auth_query_param_hint_for_unrelated_param() {
        assert_eq!(find_auth_query_param_hint("model"), None);
        assert_eq!(find_auth_query_param_hint("page_size"), None);
    }
}
