//! Demo target for `find_ac_points_src` — exercises every AC library in
//! `datasets/ac_functions.json`, every category, and every source-scan match
//! strategy (direct / method / short-name / type-method / raw-http). Not
//! meant to compile (the crates below aren't real dependencies of this
//! project) — it exists purely as scan input, the same role
//! `examples/demo_mir.txt` plays for `find_llm_calls`.

use actix_web_httpauth::middleware::HttpAuthentication;
use actix_web_grants::authorities::AuthDetails;
use actix_identity::Identity;
use axum_login::AuthnBackend;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use jsonwebtoken::decode_header;
use casbin::CoreApi;

/// [actix-web-httpauth] type-method: associated-function middleware factory.
fn build_bearer_middleware() -> HttpAuthentication<Claims, fn() -> ()> {
    HttpAuthentication::bearer(validate_bearer_token)
}

/// [actix-web-grants] method: authorization check on an extracted identity.
fn require_admin(details: &AuthDetails<String>) -> bool {
    details.has_authority("ROLE_ADMIN".to_string())
}

/// [actix-identity] method: pull the authenticated identity's id.
fn current_user_id(identity: &Identity) -> Result<String, GetIdentityError> {
    identity.id()
}

/// [axum-login] method: authenticate a set of credentials against the backend.
async fn login(backend: &MyAuthBackend, creds: Credentials) -> Result<Option<User>, BackendError> {
    backend.authenticate(creds).await
}

/// [tower-http-auth] type-method: bearer-token validation layer constructor.
fn build_validate_layer(expected_token: &str) -> ValidateRequestHeaderLayer<ValidateBearerToken> {
    ValidateRequestHeaderLayer::bearer(expected_token)
}

/// [jsonwebtoken] direct: fully-qualified call with turbofish generics.
fn verify_token(token: &str, key: &DecodingKey, validation: &Validation) -> Result<TokenData<Claims>, Error> {
    jsonwebtoken::decode::<Claims>(token, key, validation)
}

/// [jsonwebtoken] short-name: bare call via an aliased single-item import.
fn peek_header(token: &str) -> Result<Header, Error> {
    decode_header(token)
}

/// [casbin-rs] method: policy-enforcement decision.
fn check_permission(enforcer: &casbin::Enforcer, sub: &str, obj: &str, act: &str) -> bool {
    enforcer.enforce((sub, obj, act)).unwrap_or(false)
}

/// [oso] method: policy-enforcement decision via the Oso engine.
fn oso_allows(oso: &oso::Oso, actor: &Actor, action: &str, resource: &Resource) -> bool {
    oso.is_allowed(actor, action, resource).unwrap_or(false)
}

/// [biscuit-auth] method: token authorization.
fn authorize_biscuit(authorizer: &mut biscuit_auth::Authorizer) -> Result<usize, biscuit_auth::error::Token> {
    authorizer.authorize()
}

/// [raw-http-authz] with an AC path hint nearby -> reported by default.
async fn introspect_token(client: &reqwest::Client, base: &str, token: &str) -> reqwest::Result<reqwest::Response> {
    let url = format!("{base}/introspect");
    client.post(url).form(&[("token", token)]).send().await
}

/// [raw-http-authz] no AC path hint nearby -> suppressed unless
/// --all-http-calls is passed.
async fn ping_health(client: &reqwest::Client, base: &str) -> reqwest::Result<reqwest::Response> {
    client.get(format!("{base}/health")).send().await
}
