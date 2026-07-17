# AC (Access Control) Finder

A tool that scans a Rust program's compiled output and reports every location
where it performs an access-control decision — authentication (verifying
identity: JWT/session checks), authorization (RBAC/ABAC permission checks),
or policy enforcement (Casbin/Oso-style engines). No source code changes
required — it works from RUPTA's static analysis output, exactly like the
sibling [LLM API Finder](./LLM_API_FINDER.md).

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
frontend or a Node.js backend. `find_ac_points_all` runs all three scans in
one pass and merges the results.

## Supported libraries

| Library | What it covers |
|---|---|
| `actix-web-httpauth` | Bearer/basic HTTP authentication middleware for actix-web |
| `actix-web-grants` | Role/permission-based authorization middleware for actix-web |
| `actix-identity` | Session identity extraction for actix-web |
| `axum-login` | Session-based authentication and authorization backends for axum |
| `tower-http-auth` | `ValidateRequestHeaderLayer`/`AsyncRequireAuthorizationLayer` tower middleware |
| `jsonwebtoken` | JWT signature/claims verification (`decode`, `decode_header`) |
| `casbin-rs` | Casbin policy enforcement (`enforce`, `enforce_mut`) |
| `oso` | Oso policy engine (`is_allowed`) |
| `biscuit-auth` | Biscuit token authorization (`Authorizer::authorize`) |
| `raw-http-authz` | Direct HTTP calls to an external auth service (no SDK) |

## Build

```sh
cargo build --release
```

Produces `find_ac_points`, `find_ac_points_src`, `find_ac_points_js`, and
`find_ac_points_all` in `target/release/`, alongside the LLM finder binaries.

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

For a worked example exercising every library, category, and match strategy
in one file, see `examples/src/ac_demo.rs` and
[`examples/ac_demo_src.expected.md`](../examples/ac_demo_src.expected.md).

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
  "raw_line": "enforcer.enforce((sub, obj, act)).unwrap_or(false)"
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
  "raw_line": "_4 = jsonwebtoken::decode::<Claims>(move _1, move _2, move _3) -> [return: bb1, unwind continue];"
}
```

- `library` — which access-control mechanism was detected
- `category` — `authentication` | `authorization` | `policy-enforcement` | `raw-http`
- `callsite.function` — the Rust function in your program that made the call
- `raw_line` — the exact line from the analysis output that matched
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

## Known blind spots

**Attribute macros and derive-based guards** — some crates express access
control via proc-macro attributes (e.g. a hypothetical `#[require_role("admin")]`)
that are fully expanded before MIR is emitted, so no distinguishing call site
survives to scan. If a MIR dump shows zero AC-related calls for a codebase you
know enforces access control, check for this before concluding there's a gap.

**Trait-object dispatch** — like the LLM finder, calls made through a `dyn
Trait` or generic bound resolved only at monomorphization time can appear
under a different symbol shape than the cataloged one; `short-name` matching
covers the common cases but isn't exhaustive.

## Troubleshooting

Same as [`find_llm_calls`'s troubleshooting section](./LLM_API_FINDER.md#troubleshooting) —
datasets-path, RUPTA toolchain pinning, and match-strategy caveats all apply
identically here.
