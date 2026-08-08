//! Demo target for `find_ac_points_src` — exercises every AC library in
//! `datasets/ac_functions.json`, every category, and every source-scan match
//! strategy (direct / method / short-name / type-method / trait-impl /
//! type-usage / http-auth-header / header-map-insert / query-param-auth /
//! raw-http). Not meant to compile (the
//! crates below aren't real dependencies of this project) — it exists purely
//! as scan input, the same role `examples/demo_mir.txt` plays for
//! `find_llm_calls`.

use actix_web_httpauth::middleware::HttpAuthentication;
use actix_web_grants::authorities::AuthDetails;
use actix_identity::Identity;
use axum_login::AuthnBackend;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use jsonwebtoken::decode_header;
use casbin::CoreApi;
use ldap3::LdapConn;
use oauth2::AuthorizationCode;
use yup_oauth2::authenticator::Authenticator;
use argon2::PasswordVerifier;
use std::collections::HashMap;
use axum::extract::FromRequestParts;
use axum_extra::extract::TypedHeader;
use axum_extra::headers::{authorization::Bearer, Authorization};
use actix_web::FromRequest;
use db::authz;
use reqwest::Client;

/// [actix-web-httpauth] type-method: associated-function middleware factory.
fn build_bearer_middleware() -> HttpAuthentication<Claims, fn() -> ()> {
    HttpAuthentication::bearer(validate_bearer_token)
}

/// [actix-web-grants] method: authorization check on an extracted identity.
fn require_admin(details: &AuthDetails<String>) -> bool {
    details.has_authority("ROLE_ADMIN".to_string())
}

/// [actix-web-grants] attribute: proc-macro guard on the handler itself,
/// rather than a call inside its body -- exercises the "attribute" match
/// strategy (`scan_attribute_guards`).
#[has_permissions("ROLE_ADMIN")]
async fn admin_only_handler() -> impl Responder {
    "ok"
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

/// [ldap3] method: LDAP bind authentication. Fires two matches on the single
/// call below, not one -- both cataloged ldap3 signatures share their method
/// name, and method-call syntax loses the receiver's concrete type, so both
/// signatures' matchers fire identically. Expected, not a bug -- see
/// tests/fixtures.rs.
fn ldap_login(conn: &mut LdapConn, dn: &str, password: &str) -> ldap3::result::Result<ldap3::LdapResult> {
    conn.simple_bind(dn, password)
}

/// [oauth2] method: authorization-code token exchange.
fn exchange_oauth_code(client: &oauth2::basic::BasicClient, code: String) -> oauth2::basic::BasicRequestTokenResult {
    client.exchange_code(AuthorizationCode::new(code))
}

/// [yup-oauth2] type-method: Google service-account OAuth2 token fetch --
/// the yup-oauth2 analog of exchange_oauth_code above, seen auditing hub's
/// Vertex AI provider. Uses associated-function call syntax
/// (`Authenticator::token(auth, ...)`) rather than the more idiomatic
/// `auth.token(...)` deliberately -- bare `.token(` would also match
/// actix-web-httpauth's `BearerAuth::token` (imported above for
/// build_bearer_middleware), the same cross-crate method-name collision
/// class as the whoami/Bearer::token case further down, and this keeps that
/// case isolated to its one dedicated example.
async fn fetch_google_token(auth: &Authenticator<HttpsConnector>, scopes: &[&str]) -> Result<AccessToken, YupError> {
    Authenticator::token(auth, scopes).await
}

/// [bcrypt] direct: fully-qualified password-hash verification call.
fn check_password(password: &str, hash: &str) -> bcrypt::BcryptResult<bool> {
    bcrypt::verify(password, hash)
}

/// [argon2] method: password-hash verification via the PasswordVerifier trait.
fn check_password_argon2(hasher: &argon2::Argon2, password: &[u8], parsed: &argon2::PasswordHash) -> Result<(), argon2::password_hash::Error> {
    hasher.verify_password(password, parsed)
}

/// [axum-extractors] trait-impl: hand-rolled auth guard, no axum-login/
/// actix-identity involved -- gated on the "Authorization" signal in the body.
struct AuthedUser {
    user_id: String,
}

impl<S> FromRequestParts<S> for AuthedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.headers.get("Authorization").ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(AuthedUser { user_id: decode_user_id(token)? })
    }
}

/// [actix-web-extractors] trait-impl: the actix-web analog to the axum guard
/// above -- same idiom, different trait/crate.
struct ActixAuthedUser {
    user_id: String,
}

impl FromRequest for ActixAuthedUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req.headers().get("Authorization").cloned();
        Box::pin(async move { decode_actix_user(token).await })
    }
}

/// [axum-extractors] type-usage: typed bearer-header extraction as a handler
/// parameter. Deliberately returns the extracted Bearer as-is rather than
/// pulling the token string out of it -- this file also imports
/// actix-web-httpauth (a different crate, cataloged separately) elsewhere
/// above, sharing an accessor method name with axum-extra's Bearer type.
/// Method-call syntax discards the receiver's concrete type entirely, so two
/// crates that are both genuinely `use`-imported (as both are here) and
/// happen to share a method name are still irreducibly ambiguous -- no
/// amount of crate-reference *proximity* checking resolves it, since a real
/// `use` import is legitimately file-wide evidence regardless of distance
/// from the call. Not fixable without real type inference (see "Known blind
/// spots" in AC_FINDER.md) -- just avoided here to keep this file's match
/// count predictable.
async fn whoami(TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>) -> Bearer {
    bearer
}

/// [custom-authz-module] type-method: a target's own in-house authz module,
/// cataloged as a worked example (see "Adding a new library" in
/// AC_FINDER.md) -- caught by the ordinary type-method matcher, same as any
/// other library above, no scanner code needed.
async fn load_rbac(transaction: &Transaction<'_>, authentication: &Authentication, team_id: i32) -> Result<Rbac, TokioPostgresError> {
    authz::get_permissions(transaction, authentication, team_id).await
}

/// [outbound-credential-header] http-auth-header: attaching a credential to
/// an outbound request -- the app authenticating *itself* to a downstream
/// API. Stops at the builder rather than finishing the call with a send
/// method -- the credential-attachment site is the interesting part here,
/// and finishing the call would also pull in an unrelated raw-http-authz
/// match on the same line, muddying this file's exact counts.
fn call_provider(client: &Client, api_key: &str) -> reqwest::RequestBuilder {
    client
        .post("https://api.example.com/v1/chat")
        .header("Authorization", format!("Bearer {api_key}"))
}

/// [outbound-credential-header] bearer-auth-method: reqwest's typed
/// convenience method for the same outbound-authentication role. Same
/// builder-only shape as call_provider above, for the same reason.
fn call_provider_bearer(client: &Client, token: &str) -> reqwest::RequestBuilder {
    client.post("https://api.example.com/v1/embeddings").bearer_auth(token)
}

/// [outbound-credential-header] header-map-insert: attaching a credential via
/// a hand-built header map instead of chaining reqwest's builder -- the
/// idiom used by HTTP clients that take a header map directly (e.g.
/// opentelemetry-otlp's `SpanExporter::builder().with_headers(...)`), seen
/// auditing hub's OTel exporter setup.
fn build_otel_headers(api_key: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {api_key}"));
    headers
}

/// [outbound-credential-header] query-param-auth: attaching a credential as a
/// URL query parameter instead of a header -- the Gemini Developer API's
/// `?key=` idiom. `model` alongside it must not be reported -- only
/// `AUTH_QUERY_PARAM_NAMES` entries are.
fn call_gemini(client: &Client, api_key: &str, model: &str) -> reqwest::RequestBuilder {
    client
        .get("https://generativelanguage.googleapis.com/v1beta/models")
        .query(&[("model", model), ("key", api_key)])
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
