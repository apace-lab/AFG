# AC (Access Control) Finder

A family of tools that scan a Rust (or, via the LLVM-IR path, C/C++)
program's source, compiled MIR, or compiled LLVM IR and report every
location where it performs an access-control decision — authentication
(verifying identity: JWT/session checks), authorization (RBAC/ABAC
permission checks), or policy enforcement (Casbin/Oso-style engines). No
source code changes required — the MIR path works from RUPTA's static
analysis output, exactly like the sibling [LLM API
Finder](./LLM_API_FINDER.md).

## What it does

Given a program analysis file (MIR dump), `find_ac_points` tells you:

- **Which access-control mechanism** is being invoked (e.g. `jsonwebtoken`, `casbin-rs`)
- **Which category** it falls under — `authentication`, `authorization`,
  `policy-enforcement`, or `raw-http`
- **Which function** in the program makes the call
- **Where exactly** in the code that call occurs
- **Which access-control service**, best-effort, when the call is a raw HTTP
  request rather than through an SDK (see `ac_hint` under [JSON output](#json-output))

Results are printed to the terminal and saved as a JSON file, in the same
shape as `find_llm_calls`'s output.

If you don't have (or don't want to run) a RUPTA MIR dump, `find_ac_points_src`
scans Rust `.rs` source files directly — same signature catalogue, same JSON
shape, no analysis pipeline required. See [Scanning Rust source
directly](#scanning-rust-source-directly) below.

For the JS/TS side of a mixed Rust+frontend app, see the companion tool
[`find_ac_points_js`](./AC_FINDER_JS.md) — RUPTA only analyzes Rust, so it
cannot see access-control middleware/guards/decorators written in a JS/TS
frontend or a Node.js backend.

If you have (or can generate) a real LLVM IR module instead of a RUPTA MIR
dump — text `.ll` or bitcode `.bc`, from `rustc --emit=llvm-ir`/`llvm-bc` or
from clang for a C/C++ target — `find_ac_points_llvm` scans that directly, no
RUPTA toolchain needed. See [Scanning real LLVM
IR](#scanning-real-llvm-ir) below.

`find_ac_points_all` runs all of the above scans it's given paths for in one
pass and merges the results.

## Supported libraries

| Library | What it covers |
|---|---|
| `actix-web-httpauth` | Bearer/basic HTTP authentication middleware for actix-web |
| `actix-web-grants` | Role/permission-based authorization middleware for actix-web, plus its `#[has_permissions(...)]`/`#[has_roles(...)]`/`#[has_any_role(...)]`/`#[has_any_permission(...)]` proc-macro attribute guards — attributes are `find_ac_points_src` only, see [Attribute-macro guards](#attribute-macro-guards) |
| `actix-identity` | Session identity extraction for actix-web |
| `axum-login` | Session-based authentication and authorization backends for axum |
| `tower-http-auth` | `ValidateRequestHeaderLayer`/`AsyncRequireAuthorizationLayer` tower middleware |
| `jsonwebtoken` | JWT signature/claims verification (`decode`, `decode_header`) |
| `casbin-rs` | Casbin policy enforcement (`enforce`, `enforce_mut`) |
| `oso` | Oso policy engine (`is_allowed`) |
| `biscuit-auth` | Biscuit token authorization (`Authorizer::authorize`) |
| `ldap3` | LDAP bind/authentication (`LdapConn::simple_bind`, `Ldap::simple_bind`) |
| `oauth2` | OAuth2 authorization-code token exchange (`Client::exchange_code`) |
| `yup-oauth2` | Google service-account OAuth2 token fetch (`Authenticator::token`) — the yup-oauth2 analog of `oauth2` above, seen in the wild authenticating an app to Google Vertex AI/Cloud APIs |
| `bcrypt` | bcrypt password hash verification (`bcrypt::verify`) |
| `argon2` | Argon2 password hash verification (`PasswordVerifier::verify_password`) |
| `axum-extractors` | Custom axum auth guards (`impl FromRequestParts for MyUser`), typed bearer/basic header extraction (`Authorization<Bearer>`/`Authorization<Basic>`), and handler-parameter *usage* of an already-defined guard type (`current_user: MyUser`) — `find_ac_points_src` only, see below |
| `actix-web-extractors` | Custom actix-web auth guards (`impl FromRequest for MyUser`) and handler-parameter usage of one — the actix-web analog to `axum-extractors` above, same idiom and code path — `find_ac_points_src` only, see below |
| `custom-authz-module` | Worked example of a target's own in-house authz module (`db::authz::get_permissions`/`set_row_level_security_user_id`, from auditing `bionic-gpt`) — caught by the ordinary `direct`/`type-method` matchers, no scanner code needed; see [Adding a new library](#adding-a-new-library) |
| `outbound-credential-header` | The app authenticating *itself* as a client: `.header("Authorization"/"x-api-key"/"api-key"/"x-goog-api-key", ...)`, `.bearer_auth(...)`, `.basic_auth(...)`, or `.query(&[("key", ...)])` (a URL-query-parameter credential, e.g. the Gemini Developer API's `?key=`) on a `reqwest::RequestBuilder`, the same credential inserted into a hand-built header map (`headers.insert("Authorization", ...)`) for a non-reqwest HTTP client, or a *dynamic* (variable, not literal) header name passed to `.header(...)` when the file also has an auth-flavored signal somewhere in it — `find_ac_points_src` only, see below |
| `inbound-credential-header` | The mirror image of `outbound-credential-header`: a hand-rolled check of an *incoming* request's headers (`headers.get("Authorization")`, `req.headers().get("x-api-key")`) rather than a structured extractor — `find_ac_points_src` only, see below |
| `raw-http-authz` | Direct HTTP calls to an external auth service (no SDK) |

## Build

```sh
cargo build --release
```

Produces `find_ac_points`, `find_ac_points_src`, `find_ac_points_js`, and
`find_ac_points_all` in `target/release/`, alongside the LLM finder binaries.

`find_ac_points_llvm` is not part of this default build — see [Scanning real
LLVM IR](#scanning-real-llvm-ir) for why and how to opt in.

## Usage

```sh
# release build (faster)
./target/release/find_ac_points --mir <MIR_DUMP> [--datasets <DIR>] [--out <FILE>]

# or with cargo directly (no separate build step needed)
cargo run --bin find_ac_points -- --mir <MIR_DUMP> [--datasets <DIR>] [--out <FILE>]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--mir` | yes | — | Path to the RUPTA MIR dump to scan |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions.json` |
| `--out` | no | `ac_matches.json` | Where to write the JSON report |

For a worked example exercising every library that applies to MIR call-shape
matching (all of them except `axum-extractors`, `actix-web-extractors`,
`outbound-credential-header`, and `inbound-credential-header` — see [Scanning
Rust source directly](#scanning-rust-source-directly) for why those four are
`find_ac_points_src`-only), every category, and every match strategy
(`direct`, `angle-bracket`, `short-name`) in one file, see
`examples/ac_demo_mir.txt` — hand-written text in RUPTA's MIR-dump shape
rather than a real RUPTA run, the same role `examples/src/ac_demo.rs` plays
for `find_ac_points_src`. `tests/fixtures.rs` runs it and checks the JSON
output on every `cargo test`.

### Crate-reference gating for `short-name` matches

`short-name` (last two path segments, e.g. `CoreApi::enforce` for
`casbin::CoreApi::enforce`) is unanchored by nature — it has to match
whatever the MIR/LLVM callee text actually is, which for a trait method
called through a generic bound can be just the type/trait name with no crate
prefix at all. Left completely open, an unrelated local type sharing that
method name (some other `CoreApi::enforce`, nothing to do with casbin) would
misreport as a real match. Both `find_ac_points` and `find_ac_points_llvm`
require the signature's crate root to appear elsewhere in the dump/module
before accepting a `short-name` match — a type declaration mentioning
`casbin::` anywhere in the MIR text, or another function/declaration in the
LLVM module whose demangled name is rooted in `casbin` — computed once up
front as a set, not re-scanned per candidate. This is a simpler, whole-file/
whole-module version of the same idea `find_ac_points_src` applies to its
own `method`/`short-name`/`type-method` strategies (see [Cross-crate
method-name collisions in `find_ac_points_src`](#known-blind-spots) below for
why that one is windowed instead).

## Generating a MIR dump

Same procedure as `find_llm_calls` — see [LLM API Finder: Generating a MIR
dump](./LLM_API_FINDER.md#generating-a-mir-dump).

## Scanning Rust source directly

`find_ac_points_src` scans `.rs` source text directly — no MIR dump or RUPTA
toolchain needed. It reuses the same `ac_functions.json` catalogue as
`find_ac_points`, but matches call *syntax* instead of MIR's fully-qualified
UFCS form: a fully-qualified call (`jsonwebtoken::decode(...)`) is `direct`;
method-call syntax (`enforcer.enforce(...)`) is `method`; a bare call from an
aliased import (`use jsonwebtoken::decode; ...; decode(...)`) is
`short-name`; an associated-function/constructor call after importing just
the type (`use actix_web_httpauth::middleware::HttpAuthentication; ...;
HttpAuthentication::bearer(...)`) is `type-method`. The `method`,
`short-name`, and `type-method` strategies are gated behind the signature's
crate being referenced somewhere in the file (an explicit `use`, or any other
fully-qualified use of the same crate), since names like
`enforce`/`decode`/`authorize`/`login` are common words that would otherwise
produce false positives on unrelated types — and a `fn login(...)`
declaration is never mistaken for a call to that name either.

### Alias resolution

A `use path::name as alias;` import renames a symbol at the call site, and
without resolving it back to the real path, `short-name`'s bare-identifier
matching would silently miss it: `use jsonwebtoken::decode as jwt_decode;
...; jwt_decode(...)` doesn't textually contain `decode` anywhere the
boundary check accepts, so it's a false negative with no other mitigation. A
single-hop, per-file resolver (`collect_use_aliases` in
`src/ac_finder_rs_src.rs`) covers the two common `use`-aliasing shapes — `use
a::b::c as d;` and `use a::b::{c as d, ...};` — and reports the resolved call
under two more match strategies:

- `short-name-alias` — a free-function alias, e.g. the `jwt_decode` example
  above.
- `type-method-alias` — a type alias used for an associated-function call,
  e.g. `use actix_web_httpauth::middleware::HttpAuthentication as Auth; ...;
  Auth::bearer(...)`.

The `use ... as alias` statement is itself the strongest possible import
evidence — stronger than `crate_is_referenced_near`'s nearby-reference
fallback — so neither strategy is gated any further. This is intentionally
narrow: only a single hop (`use a::b::c as d; ...; let e = d; e(...)` doesn't
resolve `e`), and only the two `use`-tree shapes above (no arbitrarily nested
groups).

### Attribute-macro guards

Some crates express access control as a proc-macro *attribute* on the
handler function rather than a call inside its body — actix-web-grants'
`#[has_permissions(...)]`/`#[has_roles(...)]`/`#[has_any_role(...)]`/
`#[has_any_permission(...)]` being the concrete, verifiable case in the
catalog today (`"kind": "attribute"` entries — see [Adding a new
library](#adding-a-new-library)). `scan_attribute_guards` finds these via the
same boundary-anchored, crate-gated regex approach as `short-name`, reports
them with `match_strategy: "attribute"`, and — since the attribute sits
*above* the function it decorates rather than inside it — attributes the
match to the *next* `fn` declaration in the file (`following_function`)
instead of the last one seen (`enclosing_function`, which every other
strategy uses). See [Known blind spots](#known-blind-spots) for what this
does and doesn't cover.

Two more match strategies are `find_ac_points_src`-only, since they detect
*definition*/*type-usage* sites rather than calls — the idiomatic pattern for
apps that hand-roll an auth guard instead of pulling in axum-login/
actix-identity/etc.:

- `trait-impl` — a custom `impl FromRequestParts<S> for MyAuthedUser { ... }`
  (axum) or `impl FromRequest for MyAuthedUser { ... }` (actix-web) extractor,
  gated on `axum`/`actix_web` being referenced in the file *and* an
  auth-flavored signal (`Authorization`, `Bearer`, `jwt`, `session`, `cookie`,
  `credential`, `x-forwarded`, `permission`, `rbac`, case-insensitive) found
  in the impl body or header line — this is what keeps a non-auth extractor
  like `impl FromRequestParts for ConnectInfo` from being reported. Both
  frameworks share the same detection code (`scan_trait_impl_extractor` in
  `src/ac_finder_rs_src.rs`) and signal keyword table; only the regex/trait
  name and crate differ. actix-web's `FromRequest` regex requires a trailing
  word boundary so it doesn't also match as a prefix of axum's
  `FromRequestParts` — see `RE_ACTIX_FR_IMPL`'s doc comment.
- `type-usage` — `Authorization<Bearer>`/`Authorization<Basic>` from
  `axum-extra`'s typed-header extraction (`TypedHeader<Authorization<Bearer>>`
  as a handler parameter), gated on `axum_extra` or `headers` being
  referenced.
- `extractor-param-usage` — the other half of the `trait-impl` pattern above:
  a real app's handlers essentially never re-implement `FromRequestParts`/
  `FromRequest`, they just take the already-defined guard type as an ordinary
  parameter (bionic-gpt's `current_user: Jwt` in ~50 different handler
  files, one `impl FromRequestParts for Jwt` in `jwt.rs`). `scan_ac_rs_path`
  runs a first pass over the whole tree collecting every `trait-impl` type
  name it finds (`detect_local_auth_extractors`), then a second pass looks
  for `ident: TypeName` in a parameter-list position (`scan_extractor_param_usage`)
  for every collected type, in every file — including ones that never define
  or import the guard type's `impl` themselves. A standalone
  `scan_ac_rs_source` call (single file/string, as `find_ac_points_src --src
  <file>` or this module's tests use it) only sees types defined in that same
  call's content — the cross-file registry is populated by `scan_ac_rs_path`
  via `AcRsScanOptions::known_auth_extractors`. Matches on a struct field of
  the guard type too (not just a function parameter), since there's no real
  parser here to distinguish the two — see [Known blind
  spots](#known-blind-spots).

A third pair covers `outbound-credential-header`: the app authenticating
*itself* as a client of a downstream API (an LLM provider, a third-party
REST API, ...), the mirror image of the inbound guards above:

- `http-auth-header` — `.header("NAME", ...)` on a `reqwest::RequestBuilder`,
  gated on the header *name* itself being a known credential header
  (`Authorization`, `x-api-key`, `api-key`, `x-goog-api-key`,
  `ocp-apim-subscription-key` — see `AUTH_HEADER_NAMES` in
  `src/ac_hints.rs`), not on crate-reference alone — `.header("Content-Type",
  ...)` must never fire, so the header name is the actual gate here rather
  than a false-positive-reduction extra.
- reqwest's typed `.bearer_auth(...)`/`.basic_auth(...)` convenience methods
  are unambiguous enough to ride the ordinary `method` strategy from the
  catalogue above — no special-case code needed for those two.
- `header-map-insert` — `headers.insert("NAME", ...)` on a hand-built header
  map/`HashMap` (the non-reqwest idiom, e.g. opentelemetry-otlp's
  `SpanExporter::builder().with_headers(map)`), same header-name gate as
  `http-auth-header` above plus one more: `.insert(` is a far more generic
  method name than `.header(` (`HashMap`/`BTreeMap`/`Vec`/DB rows/... all use
  it), so the receiver identifier is additionally required to contain
  "header" (`headers`/`header_map`/...) before the header-name gate is even
  checked — see `RE_HEADER_MAP_INSERT` in `src/ac_finder_rs_src.rs`.
- `query-param-auth` — `.query(&[("NAME", ...), ...])` on a
  `reqwest::RequestBuilder`: the URL-query-string sibling of
  `http-auth-header`, for APIs that take the credential as `?key=...`
  instead of a header (most notably the Gemini Developer API). Gated on
  `reqwest` being referenced (same as `http-auth-header`) plus a known
  credential param name (`key`, `api_key`, `apikey`, `access_token`,
  `client_secret` — see `AUTH_QUERY_PARAM_NAMES` in `src/ac_hints.rs`), but
  scans the *whole* call's argument list rather than one string per call —
  `.query(...)` commonly carries several params in one list/map literal, not
  one call per param the way `.header(...)` is. `"key"` alone is
  meaningfully riskier than anything in `AUTH_HEADER_NAMES` (sort keys,
  cache keys, primary keys, ... are common unrelated query-param names too);
  accepted anyway to catch the single most common real-world case, the same
  trade-off already made for the `token` method name elsewhere in this
  catalogue (see [Known blind spots](#known-blind-spots)).
- `http-auth-header-dynamic` — the same `.header(...)` call shape as
  `http-auth-header`, but for a header *name* that's a variable/field rather
  than a string literal (e.g. bionic-gpt's
  `tool-runtime/builtin_tools/openapi_tool_adapter.rs`, which builds a
  per-integration `(String, String)` header pair from a config field in one
  method and applies it via a generic `for (name, value) in headers {
  request = request.header(name, value); }` in another). Since the literal
  header-name gate structurally can't see a variable's value, this is gated
  on an auth-flavored signal word (`bearer`, `authoriz`, `api_key`,
  `access_token`, `credential`, ...) appearing *anywhere in the file* instead
  of a nearby-line window — the code that determines a dynamic header's real
  name is routinely tens of lines away from, and can textually precede, the
  generic call that actually attaches it. This is meaningfully lower
  precision than every other strategy in this table (a file-wide gate, not a
  windowed or line-local one), so every match's `ac_hint` says "verify
  manually" rather than describing the header with confidence.

For a worked example exercising every library, category, and match strategy
in one file, see `examples/src/ac_demo.rs`. `tests/fixtures.rs` runs it and
checks the JSON output on every `cargo test`.

### Inbound credential-header checks

`inbound-credential-header` is the mirror image of
`outbound-credential-header` above: a hand-rolled check of an *incoming*
request's headers, for apps that don't use a structured extractor
(`FromRequestParts`/`TypedHeader<Authorization<Bearer>>`) at all — e.g.
bionic-gpt's `crates/web-server/handlers/api_pipeline.rs`, which reads
`headers.get("Authorization")` off an axum `HeaderMap` and checks the token
against the database by hand. One match strategy, two call shapes:

- `inbound-auth-header` — `headers.get("NAME")` / `parts.headers.get("NAME")`
  (a `HeaderMap` field access, axum's idiom), gated the same way
  `header-map-insert` is: the header name must be a known credential header
  (`AUTH_HEADER_NAMES`) *and* the receiver identifier must contain "header"
  (`.get(` alone is far too generic — `HashMap`/`Option`/`Vec`/... all have
  one). The same strategy also covers actix-web's `req.headers().get("NAME")`
  (a method call, not a field, so it's matched by a second, dedicated regex
  anchored on the explicit `.headers().get(...)` chain instead of the
  receiver-name gate).

For a worked example, see `examples/src/ac_demo.rs`'s `from_request_parts`/
`from_request` functions — the same custom axum/actix-web guards that
demonstrate `trait-impl` above also read their token from an inbound
`Authorization` header, so both patterns fire on the same lines.

```sh
./target/release/find_ac_points_src --src <FILE_OR_DIR> [--datasets <DIR>] [--out <FILE>]

# or with cargo directly
cargo run --bin find_ac_points_src -- --src <FILE_OR_DIR> [--datasets <DIR>] [--out <FILE>]
```

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--src` | yes | — | Rust source file or directory to scan |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions.json` |
| `--out` | no | `ac_matches_src.json` | Where to write the JSON report |
| `--all-http-calls` | no | off | Report every `.send(`-shaped call once `reqwest` is referenced, even without a known AC path hint nearby |
| `--include-target-dir` | no | off | Also scan `target/` (build output) |

Each match in `ac_matches_src.json` carries the same `library`/`fn_name`/
`category`/`ac_hint` fields as `find_ac_points`'s output, but the callsite
and match-strategy shape reflects real source rather than MIR:

```json
{
  "library": "casbin-rs",
  "fn_name": "casbin::CoreApi::enforce",
  "category": "policy-enforcement",
  "match_strategy": "method",
  "callsite": {
    "file": "src/authz.rs",
    "function": "check_permission",
    "line": 10
  },
  "parameters": ["(sub, obj, act)"],
  "raw_line": "enforcer.enforce((sub, obj, act)).unwrap_or(false)",
  "verified_via": "general-knowledge"
}
```

- `callsite.function` — enclosing Rust function, best-effort (last `fn`
  declaration seen before the call site; a text-scan heuristic, not
  scope-aware — see `src/ac_finder_rs_src.rs`)
- `parameters` — the actual top-level argument texts at this call site, in
  source order (not the SDK's declared parameter types)

`find_ac_points_all --rs-src <DIR>` runs this scan alongside (or instead of)
the MIR and JS/TS scans and merges all three into one report, under
`rust_src_matches`.

## Scanning real LLVM IR

`find_ac_points_llvm` scans an actual LLVM IR module — text `.ll` or bitcode
`.bc` — using the [`llvm-ir`](https://github.com/cdisselkoen/llvm-ir) crate
to parse it into typed structures and walk `call` instructions directly,
rather than regex-scanning a text dump the way `find_ac_points` does. It
reuses the same `ac_functions.json` catalogue: each `call` target's mangled
linkage name is demangled with
[`rustc-demangle`](https://github.com/rust-lang/rustc-demangle) before being
matched, so the catalogue's plain Rust paths (`jsonwebtoken::decode`) line up
with what the IR actually carries (`_ZN12jsonwebtoken6decodeE`).

This is the tool to reach for when you have LLVM IR from a build that never
goes through RUPTA at all — e.g. `rustc --emit=llvm-ir` directly, or a
C/C++ target compiled with clang that links against a C access-control
library. See `src/ac_finder_llvm.rs` for the implementation.

### Why it's opt-in

Unlike every other dependency in this repository, `llvm-ir` pulls in
`llvm-sys`, which needs a **real LLVM installation** at build time (headers,
libraries, and `llvm-config` on `PATH`), pinned to one specific major
version. That's a system requirement plain `cargo build` has never had here,
so it's gated behind an opt-in Cargo feature, `llvm-ir-scan`, rather than a
default dependency — without it, `cargo build`/`cargo test` behave exactly
as before for everyone who doesn't need this scanner.

```sh
# needs LLVM 19 installed (llvm-config on PATH) -- this crate is pinned to
# the "llvm-19" feature of llvm-ir (the newest it supports); see
# "Retargeting a different LLVM version" below if you're on a different one
cargo build --release --features llvm-ir-scan
```

This produces `find_ac_points_llvm` in `target/release/`, and also enables
the `--llvm-ir` flag on `find_ac_points_all` (a 4th stage merged in
alongside the MIR/Rust-source/JS-TS scans). Building without the feature
still produces `find_ac_points_all`, but passing `--llvm-ir` to it is then a
runtime error telling you to rebuild with `--features llvm-ir-scan`.

### Getting a working LLVM 19 toolchain

`llvm-sys` needs `llvm-config` on `PATH` (or `LLVM_SYS_191_PREFIX` pointing
at a prefix containing it) at build time — not just the LLVM tools/DLLs, a
full development install with `llvm-config` and the per-component static
libraries.

- **Linux**: your distro's `llvm-19-dev` package (Debian/Ubuntu) or
  equivalent is normally sufficient. On Debian/Ubuntu you also need
  `libpolly-19-dev` and `libzstd-dev` for a full static link (`llvm-19-dev`
  alone builds but fails at link time with "could not find native static
  library `Polly`" / "unable to find library -lzstd" otherwise).
- **Windows**: the official LLVM installer (`winget install LLVM.LLVM`, or
  the `.exe` from [releases.llvm.org](https://releases.llvm.org/)) does
  **not** ship `llvm-config.exe` or per-component static libs — only DLL
  import libraries and no `include/` headers — so `llvm-sys` cannot build
  against it regardless of `LLVM_SYS_191_PREFIX`. Either build LLVM 19 from
  source (CMake + Ninja + MSVC), or use WSL and a Linux `llvm-19-dev`
  package as above; there's no shortcut through the native Windows
  installer today.
- **macOS**: Homebrew's `llvm@19` includes `llvm-config` and was
  auto-discovered here with no env var needed; if it isn't found, set
  `LLVM_SYS_191_PREFIX=$(brew --prefix llvm@19)` since it's keg-only.

### Retargeting a different LLVM version

This is pinned to LLVM 19 in `Cargo.toml` — the newest version `llvm-ir`
0.11.x supports:

```toml
llvm-ir = { version = "0.11", features = ["llvm-19"], optional = true }
```

If your toolchain is on a different (older) LLVM major version, change
`"llvm-19"` to the matching feature (`llvm-ir` 0.11 supports `llvm-9`
through `llvm-19` at the time of writing — check
[`llvm-ir`'s `Cargo.toml`](https://github.com/cdisselkoen/llvm-ir/blob/master/Cargo.toml)
for the current range, in case a newer `llvm-ir` release has extended it).
Only one `llvm-N` feature can be active at a time. Note this is a ceiling,
not a moving target: a *current* rustc already bundles a newer LLVM than
19 (see "Regenerating `examples/ac_demo_llvm.ll`" below), so generating
fresh IR for this scanner to read still means pinning an older rustc
regardless of which supported feature you pick.

### `find_ac_points_llvm` usage

```sh
./target/release/find_ac_points_llvm --ir <MODULE.ll|MODULE.bc> [--datasets <DIR>] [--out <FILE>]

# or with cargo directly
cargo run --release --features llvm-ir-scan --bin find_ac_points_llvm -- --ir <MODULE.ll> [--datasets <DIR>] [--out <FILE>]
```

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--ir` | yes | — | LLVM IR module to scan: text (`.ll`) or bitcode (`.bc`), dispatched on extension |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions.json` |
| `--out` | no | `ac_matches_llvm.json` | Where to write the JSON report |

For a worked example — real `rustc --emit=llvm-ir` output (not hand-written),
exercising the `direct` and `angle-bracket` match strategies against a real
trait-impl call site — see `examples/ac_demo_llvm.ll`, generated from the
source in `examples/src/ac_demo_llvm/` (see [Regenerating
`examples/ac_demo_llvm.ll`](#regenerating-examplesac_demo_llvmll) below for
how). `tests/fixtures.rs` runs it and checks the JSON output whenever
`cargo test` is run with `--features llvm-ir-scan`.

### Generating an LLVM IR module

From a Rust crate:

```sh
rustc --edition 2021 --crate-type lib --emit=llvm-ir -o out.ll src/lib.rs
# or, via cargo, for a whole crate:
RUSTFLAGS="--emit=llvm-ir" cargo build --release
# .ll files land under target/release/deps/*.ll
```

From a C/C++ target, with clang:

```sh
clang -S -emit-llvm -o out.ll src/main.c
```

Add `-g` (rustc) or `-g` (clang) to carry source file/line debug info through
into the IR — `find_ac_points_llvm` reports `callsite.file`/`callsite.line`
when present, and falls back to basic-block name + instruction index when
not.

### Regenerating `examples/ac_demo_llvm.ll`

`examples/ac_demo_llvm.ll` is real `rustc --emit=llvm-ir` output, generated
from the four small Rust source files in `examples/src/ac_demo_llvm/`:
`jsonwebtoken.rs`/`bcrypt.rs`/`casbin.rs` (minimal stand-ins for those
crates' public surface, each compiled as its own crate so real Rust mangling
gives call sites the same paths the catalogue expects) and `my_app.rs` (the
"application" crate, calling into all three plus one unrelated `format!`
call that must not be reported).

`rustc`'s bundled LLVM version has to match (or at least be understood by)
the `llvm-ir` crate's pinned parser version. A *current* `rustc` bundles a
much newer LLVM than this repo's `llvm-19` pin — rustc jumped to LLVM 20+
around the 1.85+ range — whose IR text uses newer syntax that doesn't
parse under LLVM 19's grammar, so regenerating this fixture needs an older
`rustc` whose bundled LLVM actually matches. rustc 1.82.0–1.84.x all bundle
LLVM 19.1.x:

```sh
rustup toolchain install 1.82.0   # bundles LLVM 19.1.1 -- matches our pin
cd examples/src/ac_demo_llvm
mkdir -p .build
rustc +1.82.0 --edition 2021 --crate-type lib --crate-name jsonwebtoken -o .build/libjsonwebtoken.rlib jsonwebtoken.rs
rustc +1.82.0 --edition 2021 --crate-type lib --crate-name bcrypt       -o .build/libbcrypt.rlib bcrypt.rs
rustc +1.82.0 --edition 2021 --crate-type lib --crate-name casbin       -o .build/libcasbin.rlib casbin.rs
rustc +1.82.0 --edition 2021 --crate-type lib --crate-name ac_demo_llvm \
  --extern jsonwebtoken=.build/libjsonwebtoken.rlib \
  --extern bcrypt=.build/libbcrypt.rlib \
  --extern casbin=.build/libcasbin.rlib \
  --emit=llvm-ir -o ../../ac_demo_llvm.ll \
  my_app.rs
```

If your default `rustc` already bundles LLVM 19 (check `rustc -vV`), you can
drop the `+1.82.0` toolchain overrides. Then scan it:

```sh
cargo build --release --features llvm-ir-scan
./target/release/find_ac_points_llvm --ir examples/ac_demo_llvm.ll
```

Generating IR from a *real* crate with actual dependencies (rather than
these dependency-free stand-ins) means going through Cargo, and hits a
second, independent problem on top of the LLVM-version mismatch above:
this repo's `Cargo.lock` resolves some dependency versions (e.g.
`clap_lex`) that need Cargo's `edition2024` support, which a rustc old
enough to bundle LLVM 19 doesn't have. Building such a target for
`--emit=llvm-ir` therefore needs both the pinned old rustc *and* those
dependencies temporarily downgraded to pre-`edition2024` versions (e.g.
`cargo update -p clap --precise 4.5.20` and let it cascade) — ideally done
in a scratch clone or worktree so it never touches this repo's own
`Cargo.lock`.

### Match strategies and JSON shape

Reuses the three match strategies conceptually (`direct`, `angle-bracket`,
`short-name`) from `find_ac_points`, applied to the demangled callee name
instead of a MIR text line. `short-name` is additionally gated the same way
as in `find_ac_points` (see [Crate-reference gating for `short-name`
matches](#crate-reference-gating-for-short-name-matches) below) — and
`kind: "attribute"` catalog entries are never loaded here at all (see
[Attribute-macro guards](#attribute-macro-guards)). Each match in
`ac_matches_llvm.json` looks like:

```json
{
  "library": "jsonwebtoken",
  "fn_name": "jsonwebtoken::decode",
  "category": "authentication",
  "match_strategy": "direct",
  "callsite": {
    "function": "my_app::verify_token",
    "block": "%bb0",
    "instruction_index": 3,
    "file": "src/main.rs",
    "line": 42
  },
  "mangled_name": "_ZN...",
  "demangled_name": "jsonwebtoken::decode",
  "verified_via": "general-knowledge"
}
```

- `mangled_name` / `demangled_name` — the callee's raw linkage name and what
  it demangled to (what was actually matched against the catalogue), so you
  can audit a surprising match or miss.
- `callsite.file` / `callsite.line` — only present when the module carries
  `!dbg` debug info for that instruction (`skip_serializing_if` omits them
  otherwise, same convention as `ac_hint` elsewhere in this tool).
- `ac_hint` — always absent from this scanner today; see [Known blind
  spots](#known-blind-spots).

`find_ac_points_all --llvm-ir <MODULE.ll>` runs this scan alongside the
other three and merges it into `llvm_matches` in the combined report.

## JSON output

Each match in `ac_matches.json` looks like:

```json
{
  "library": "jsonwebtoken",
  "fn_name": "jsonwebtoken::decode",
  "category": "authentication",
  "match_strategy": "direct",
  "callsite": {
    "func_id": "FuncId(4)",
    "function": "my_app::verify_token",
    "basic_block": "bb0",
    "line": 812
  },
  "raw_line": "_4 = jsonwebtoken::decode::<Claims>(move _1, move _2, move _3) -> [return: bb1, unwind continue];",
  "verified_via": "general-knowledge"
}
```

- `library` — which access-control mechanism was detected
- `category` — `authentication` | `authorization` | `policy-enforcement` | `raw-http`
- `callsite.function` — the Rust function in your program that made the call
- `raw_line` — the exact line from the analysis output that matched
- `verified_via` — copied from the matching catalogue entry's `verified_via`
  (`general-knowledge` | `docs.rs` | `manual` | `ambient` | `unspecified`):
  how trustworthy this signature's shape is, so you can triage speculative
  matches from verified ones without cross-referencing `ac_functions.json` by
  hand. Present on every match from all three Rust-side scanners
  (`find_ac_points`, `find_ac_points_src`, `find_ac_points_llvm`).
- `ac_hint` — present only on `raw-http-authz` matches. Scans string literals
  seen earlier in the same function for a known auth-service REST path
  suffix (`/introspect` → OAuth2 token introspection, `/v1/data/` → Open
  Policy Agent, `/protocol/openid-connect/token` → Keycloak, etc. — see
  `src/ac_hints.rs` for the full table). Same heuristic as `provider_hint` in
  the LLM finder: absent means no known suffix was found nearby, not that the
  call isn't access-control-related.

## Adding a new library

Edit `datasets/ac_functions.json` — no rebuild needed. Add an entry under the
library name with the function's full Rust path and a `category`:

```json
"my-authz-crate": [
  {
    "fn_name": "my_authz_crate::Guard::check",
    "category": "authorization",
    "return_type": "Result<bool, Error>",
    "parameter_type": ["&self", "Request"],
    "verified_via": "manual"
  }
]
```

This works just as well for a target's own in-house authz function, not just
a third-party crate — `custom-authz-module` in the catalogue is exactly that,
a worked example added while auditing `bionic-gpt`
(`db::authz::get_permissions`), caught by the ordinary matchers above with no
scanner code changes.

An entry can also set `"kind": "attribute"` (defaults to `"call"` when
omitted) to catalog a proc-macro attribute guard instead of a function/method
call — see [Attribute-macro guards](#attribute-macro-guards). Only
`find_ac_points_src` looks for `kind: "attribute"` entries; `find_ac_points`
and `find_ac_points_llvm` skip them entirely, since the attribute expands
away before MIR/LLVM-IR codegen and leaves no realistic callee text to match.

## Known blind spots

**Attribute macros and derive-based guards** — proc-macro attributes are
fully expanded before MIR/LLVM IR is emitted, so no distinguishing call site
survives for `find_ac_points`/`find_ac_points_llvm` to scan; `find_ac_points_src`
covers this only for the crates cataloged as `kind: "attribute"` — currently
just actix-web-grants — via [Attribute-macro guards](#attribute-macro-guards)
above. A codebase using some other crate's attribute-macro guard, or an
in-house one, is still a blind spot until it's added to the catalog. If a
MIR/LLVM-IR scan shows zero AC-related calls for a codebase you know enforces
access control, check for this (and cross-check against a `--rs-src` scan of
the same code) before concluding there's a gap.

**Trait-object dispatch** — like the LLM finder, calls made through a `dyn
Trait` or generic bound resolved only at monomorphization time can appear
under a different symbol shape than the cataloged one; `short-name` matching
covers the common cases but isn't exhaustive. `find_ac_points_llvm` has the
equivalent gap for indirect calls (function pointers, vtable dispatch): the
callee is a local SSA value rather than a `GlobalReference`, so there's no
static symbol to demangle and match against the catalogue.

**Hand-rolled auth guards in warp** — `axum-extractors`/`actix-web-extractors`
(see [Scanning Rust source directly](#scanning-rust-source-directly)) cover
axum's `FromRequestParts` and actix-web's `FromRequest` extractor patterns.
warp's equivalent (a custom `Filter` combinator, not a trait impl) isn't
covered yet — if a codebase enforces auth entirely through a hand-rolled warp
filter and pulls in none of the cataloged crates, `find_ac_points_src` will
currently under-report it the same way it did for axum/actix-web before those
patterns were added. Likely lower-value to add than axum/actix-web were: warp
is less widely used, and much of its auth idiom (`warp::header::<String>(...)`,
etc.) is already just an ordinary function call, catalogable via [Adding a new
library](#adding-a-new-library) with no scanner code changes.

**`extractor-param-usage` matches struct fields, not just handler
parameters** — `ident: TypeName` in a parameter-list position (`(`/`,`
immediately before it) also matches a struct field of that type (`user: Jwt,`
inside some unrelated `struct { ... }`), since there's no real Rust parser
here to tell the two apart. In practice this is rare (embedding an
authenticated-user type as a struct field, rather than taking it directly as
a handler parameter, isn't a common pattern) and arguably still
access-control-relevant when it happens, but it's a known imprecision, not a
verified "this is definitely a handler."

**`http-auth-header-dynamic` is a whole-file heuristic** — a `.header(name,
value)` call with a variable header name can't be resolved to its real value
from source text alone, so this strategy gates on an auth-flavored signal
word (`bearer`, `api_key`, ...) appearing *anywhere in the file*, not near the
call. This is meaningfully looser than every other gate in this catalogue: a
large file with an unrelated dynamic `.header(...)` call (e.g. copying
tracing/correlation headers onto an outbound request) plus an unrelated
mention of one of the signal words elsewhere will false-positive. Every match
from this strategy says "verify manually" in its `ac_hint` for exactly this
reason — treat it as a lead, not a confirmed finding, more so than any other
match strategy here.

**Cross-crate method-name collisions in `find_ac_points_src`** — the
`method`/`short-name` strategies match on a bare method name
(`.token(`/`.enforce(`/...) gated on the owning crate being referenced
somewhere in the file, since method-call syntax discards the receiver's
concrete type entirely. Two *different* cataloged crates that are both
genuinely `use`-imported in the same file and happen to share a method name
(e.g. `actix-web-httpauth`'s `BearerAuth::token` and `axum-extra`'s
`Bearer::token`) are irreducibly ambiguous: both gates are independently,
correctly satisfied, so a single `.token(` call site gets reported under
both libraries. `crate_is_referenced_near` (see `src/ac_finder_rs_src.rs`)
narrows the *fallback* evidence — a bare fully-qualified reference far from
the call, for import-free coding styles — to a window around the match
rather than the whole file, which does close the narrower case of two
crates' bare references landing far apart with no `use` statement at all.
It does not and cannot close the `use`-import case: a real import is
legitimately file-wide evidence regardless of distance from the call, so
narrowing that check would just break the (far more common) pattern of
imports living at the top of a file with usage well below. Actually
resolving the `use`-import case would need real type inference on the
receiver expression, out of reach for a regex-based scanner. See
`examples/src/ac_demo.rs`'s `whoami` function for a live example this
project works around rather than "fixes."

**`find_ac_points_llvm` has no `ac_hint` for `raw-http-authz` matches** —
`find_ac_points`/`find_ac_points_src` guess the access-control service behind
a raw HTTP call by scanning nearby string literals for a known REST path
suffix (see `ac_hint` in [JSON output](#json-output)). Reconstructing "nearby
string literals" from LLVM IR means resolving `getelementptr` chains into
constant globals holding `[N x i8]` byte arrays, which this scanner doesn't
attempt yet — `raw-http-authz` matches from it always carry `ac_hint: null`.

## Troubleshooting

Same as [`find_llm_calls`'s troubleshooting section](./LLM_API_FINDER.md#troubleshooting) —
datasets-path, RUPTA toolchain pinning, and match-strategy caveats all apply
identically here.
