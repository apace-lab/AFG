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
}
