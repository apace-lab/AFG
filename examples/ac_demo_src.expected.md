# Expected results: examples/src/ac_demo.rs

`examples/src/ac_demo.rs` is a demo target for `find_ac_points_src` — it
exercises every AC library in `datasets/ac_functions.json`, every category
(`authentication`, `authorization`, `policy-enforcement`, `raw-http`), and
every source-scan match strategy (`direct`, `method`, `short-name`,
`type-method`, `http+path-hint`/`http-call-only`) in one file. It doesn't
compile — the crates it references aren't real dependencies of this
project — it exists purely as scan input, the same role `examples/demo_mir.txt`
plays for `find_llm_calls`.

Run:

```sh
./target/release/find_ac_points_src --src examples/src/ac_demo.rs
```

## Terminal output

```
[find_ac_points_src] loaded 20 signatures from datasets/ac_functions.json
Found 11 access-control call site(s) in examples/src/ac_demo.rs:

  Found actix-web-httpauth [authentication] call (actix_web_httpauth::middleware::HttpAuthentication::bearer) in fn build_bearer_middleware at examples/src/ac_demo.rs:18 [type-method]
    parameters: validate_bearer_token
  Found actix-web-grants [authorization] call (actix_web_grants::authorities::AuthDetails::has_authority) in fn require_admin at examples/src/ac_demo.rs:23 [method]
    parameters: "ROLE_ADMIN".to_string()
  Found actix-identity [authentication] call (actix_identity::Identity::id) in fn current_user_id at examples/src/ac_demo.rs:28 [method]
  Found axum-login [authentication] call (axum_login::AuthnBackend::authenticate) in fn login at examples/src/ac_demo.rs:33 [method]
    parameters: creds
  Found tower-http-auth [authentication] call (tower_http::validate_request::ValidateRequestHeaderLayer::bearer) in fn build_validate_layer at examples/src/ac_demo.rs:38 [type-method]
    parameters: expected_token
  Found jsonwebtoken [authentication] call (jsonwebtoken::decode) in fn verify_token at examples/src/ac_demo.rs:43 [direct]
    parameters: token, key, validation
  Found jsonwebtoken [authentication] call (jsonwebtoken::decode_header) in fn peek_header at examples/src/ac_demo.rs:48 [short-name]
    parameters: token
  Found casbin-rs [policy-enforcement] call (casbin::CoreApi::enforce) in fn check_permission at examples/src/ac_demo.rs:53 [method]
    parameters: (sub, obj, act)
  Found oso [policy-enforcement] call (oso::Oso::is_allowed) in fn oso_allows at examples/src/ac_demo.rs:58 [method]
    parameters: actor, action, resource
  Found biscuit-auth [policy-enforcement] call (biscuit_auth::Authorizer::authorize) in fn authorize_biscuit at examples/src/ac_demo.rs:63 [method]
  Found raw-http-authz [raw-http] call (reqwest::RequestBuilder::send) in fn introspect_token at examples/src/ac_demo.rs:69 [http+path-hint]
    ac hint: OAuth2 token introspection (RFC 7662)
[find_ac_points_src] JSON written to ac_matches_src.json
```

Matches are sorted by source line, so this order is stable across runs (the
underlying signature catalogue loads from a `HashMap`-backed JSON object,
which has no stable iteration order on its own — `scan_ac_rs_source` sorts
before returning specifically to paper over that).

Note `ping_health` (line 75) is *not* in this list — it calls `.send()` too,
but with no known access-control REST path nearby, so it's suppressed by
default. See [`--all-http-calls`](#--all-http-calls-variant) below.

## JSON output

```json
{
  "matches": [
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "build_bearer_middleware",
        "line": 18
      },
      "category": "authentication",
      "fn_name": "actix_web_httpauth::middleware::HttpAuthentication::bearer",
      "library": "actix-web-httpauth",
      "match_strategy": "type-method",
      "parameters": [
        "validate_bearer_token"
      ],
      "raw_line": "HttpAuthentication::bearer(validate_bearer_token)"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "require_admin",
        "line": 23
      },
      "category": "authorization",
      "fn_name": "actix_web_grants::authorities::AuthDetails::has_authority",
      "library": "actix-web-grants",
      "match_strategy": "method",
      "parameters": [
        "\"ROLE_ADMIN\".to_string()"
      ],
      "raw_line": "details.has_authority(\"ROLE_ADMIN\".to_string())"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "current_user_id",
        "line": 28
      },
      "category": "authentication",
      "fn_name": "actix_identity::Identity::id",
      "library": "actix-identity",
      "match_strategy": "method",
      "parameters": [],
      "raw_line": "identity.id()"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "login",
        "line": 33
      },
      "category": "authentication",
      "fn_name": "axum_login::AuthnBackend::authenticate",
      "library": "axum-login",
      "match_strategy": "method",
      "parameters": [
        "creds"
      ],
      "raw_line": "backend.authenticate(creds).await"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "build_validate_layer",
        "line": 38
      },
      "category": "authentication",
      "fn_name": "tower_http::validate_request::ValidateRequestHeaderLayer::bearer",
      "library": "tower-http-auth",
      "match_strategy": "type-method",
      "parameters": [
        "expected_token"
      ],
      "raw_line": "ValidateRequestHeaderLayer::bearer(expected_token)"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "verify_token",
        "line": 43
      },
      "category": "authentication",
      "fn_name": "jsonwebtoken::decode",
      "library": "jsonwebtoken",
      "match_strategy": "direct",
      "parameters": [
        "token",
        "key",
        "validation"
      ],
      "raw_line": "jsonwebtoken::decode::<Claims>(token, key, validation)"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "peek_header",
        "line": 48
      },
      "category": "authentication",
      "fn_name": "jsonwebtoken::decode_header",
      "library": "jsonwebtoken",
      "match_strategy": "short-name",
      "parameters": [
        "token"
      ],
      "raw_line": "decode_header(token)"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "check_permission",
        "line": 53
      },
      "category": "policy-enforcement",
      "fn_name": "casbin::CoreApi::enforce",
      "library": "casbin-rs",
      "match_strategy": "method",
      "parameters": [
        "(sub, obj, act)"
      ],
      "raw_line": "enforcer.enforce((sub, obj, act)).unwrap_or(false)"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "oso_allows",
        "line": 58
      },
      "category": "policy-enforcement",
      "fn_name": "oso::Oso::is_allowed",
      "library": "oso",
      "match_strategy": "method",
      "parameters": [
        "actor",
        "action",
        "resource"
      ],
      "raw_line": "oso.is_allowed(actor, action, resource).unwrap_or(false)"
    },
    {
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "authorize_biscuit",
        "line": 63
      },
      "category": "policy-enforcement",
      "fn_name": "biscuit_auth::Authorizer::authorize",
      "library": "biscuit-auth",
      "match_strategy": "method",
      "parameters": [],
      "raw_line": "authorizer.authorize()"
    },
    {
      "ac_hint": "OAuth2 token introspection (RFC 7662)",
      "callsite": {
        "file": "examples/src/ac_demo.rs",
        "function": "introspect_token",
        "line": 69
      },
      "category": "raw-http",
      "fn_name": "reqwest::RequestBuilder::send",
      "library": "raw-http-authz",
      "match_strategy": "http+path-hint",
      "parameters": [],
      "raw_line": "client.post(url).form(&[(\"token\", token)]).send().await"
    }
  ],
  "signatures_loaded": 20,
  "src": "examples/src/ac_demo.rs",
  "total_matches": 11
}
```

## `--all-http-calls` variant

```sh
./target/release/find_ac_points_src --src examples/src/ac_demo.rs --all-http-calls
```

adds one more match — `ping_health`'s `.send()` — now reported despite
having no known AC path hint nearby:

```
  Found raw-http-authz [raw-http] call (reqwest::RequestBuilder::send) in fn ping_health at examples/src/ac_demo.rs:75 [http-call-only]
```

## What this shows

Every part of `find_ac_points_src` fires at least once:

**All 10 catalogued libraries:**

| Library | Function | Category |
|---|---|---|
| `actix-web-httpauth` | `HttpAuthentication::bearer` | authentication |
| `actix-web-grants` | `AuthDetails::has_authority` | authorization |
| `actix-identity` | `Identity::id` | authentication |
| `axum-login` | `AuthnBackend::authenticate` | authentication |
| `tower-http-auth` | `ValidateRequestHeaderLayer::bearer` | authentication |
| `jsonwebtoken` | `decode`, `decode_header` | authentication |
| `casbin-rs` | `CoreApi::enforce` | policy-enforcement |
| `oso` | `Oso::is_allowed` | policy-enforcement |
| `biscuit-auth` | `Authorizer::authorize` | policy-enforcement |
| `raw-http-authz` | `RequestBuilder::send` | raw-http |

**All 4 categories** — authentication, authorization, policy-enforcement,
raw-http — each appears at least once above.

**All 5 match strategies:**

1. **`direct`** (`verify_token`, line 43) — the fully-qualified call
   `jsonwebtoken::decode::<Claims>(...)`, turbofish and all.
2. **`method`** (e.g. `check_permission`, line 53) — receiver-syntax calls
   like `enforcer.enforce(...)`; gated behind `casbin` being referenced
   somewhere in the file (`use casbin::CoreApi;`), since `enforce` alone is
   too generic a word to trust blindly.
3. **`short-name`** (`peek_header`, line 48) — a bare call to an
   aliased single-item import (`use jsonwebtoken::decode_header;` then
   `decode_header(token)`), also import-gated.
4. **`type-method`** (`build_bearer_middleware`, line 18;
   `build_validate_layer`, line 38) — the `Type::method(...)`
   associated-function/constructor idiom (`HttpAuthentication::bearer(...)`,
   `ValidateRequestHeaderLayer::bearer(...)`), also import-gated.
5. **`http+path-hint`** / **`http-call-only`** (`introspect_token` vs.
   `ping_health`) — a raw `reqwest` `.send()` call is only reported by
   default when a known access-control REST path suffix
   (`/introspect` → OAuth2 token introspection, RFC 7662) is found in a
   nearby string literal; `--all-http-calls` reports every `.send()` once
   `reqwest` is referenced, regardless of a hint.

**Other fields demonstrated:**

- `callsite.function` — every match correctly attributes the enclosing Rust
  function (e.g. the `casbin::CoreApi::enforce` call is attributed to
  `check_permission`, not some other function in the file).
- `parameters` — the real argument text at each call site, e.g.
  `["token", "key", "validation"]` for `verify_token`, or the tuple
  `["(sub, obj, act)"]` for `check_permission`.

**A fixed false positive worth noting:** the demo originally also matched
`axum_login::AuthSession::login`'s short name against the *declaration*
`async fn login(...)` (line 32) — a bare identifier followed by `(` looks
identical to a call unless you check what comes before it. `is_fn_declaration`
in `src/ac_finder_rs_src.rs` filters this out; see the
`fn_declaration_sharing_a_signature_name_is_not_a_call` test.
