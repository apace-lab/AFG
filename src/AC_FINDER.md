# AC (Access Control) Finder

A family of tools that scan a Rust (or, via LLVM IR, C/C++) program's
source, compiled MIR, or compiled LLVM IR and report every access-control
decision point — authentication (JWT/session checks), authorization
(RBAC/ABAC checks), or policy enforcement (Casbin/Oso-style engines). No
source changes required for the MIR/LLVM-IR paths.

Four ways to scan, pick whichever fits what you have on hand:

| Tool | Scans | Needs |
|---|---|---|
| `find_ac_points` | RUPTA MIR dump | a RUPTA MIR dump |
| `find_ac_points_src` | Rust `.rs` source directly | nothing extra |
| `find_ac_points_js` | JS/TS source | nothing extra — see [AC_FINDER_JS.md](./AC_FINDER_JS.md) |
| `find_ac_points_llvm` | Real LLVM IR (`.ll`/`.bc`) | LLVM 19 installed — see [below](#scanning-real-llvm-ir) |

`find_ac_points_all` runs any combination of the first three (plus the
fourth, if built with `--features llvm-ir-scan`) in one pass and merges the
results.

## Supported libraries

| Library | What it covers |
|---|---|
| `actix-web-httpauth` | Bearer/basic HTTP auth middleware for actix-web |
| `actix-web-grants` | Role/permission authorization middleware + `#[has_permissions(...)]`-style attributes (Rust-source scan only) |
| `actix-identity` | Session identity extraction for actix-web |
| `axum-login` | Session-based auth backends for axum |
| `tower-http-auth` | `ValidateRequestHeaderLayer`/`AsyncRequireAuthorizationLayer` |
| `jsonwebtoken` | JWT verification (`decode`, `decode_header`) |
| `casbin-rs` | Casbin policy enforcement (`enforce`, `enforce_mut`) |
| `oso` | Oso policy engine (`is_allowed`) |
| `biscuit-auth` | Biscuit token authorization |
| `ldap3` | LDAP bind/authentication |
| `oauth2` | OAuth2 authorization-code token exchange |
| `yup-oauth2` | Google service-account OAuth2 token fetch |
| `bcrypt` / `argon2` | Password hash verification |
| `axum-extractors` / `actix-web-extractors` | Custom auth-guard extractors (`impl FromRequestParts`/`FromRequest`) — Rust-source scan only |
| `custom-authz-module` | Worked example of cataloguing your own in-house authz function |
| `outbound-credential-header` | App authenticating *itself* to a downstream API (`Authorization`/`x-api-key` header, `.bearer_auth(...)`, `?key=...`) — Rust-source scan only |
| `inbound-credential-header` | Hand-rolled check of an *incoming* request's auth header — Rust-source scan only |
| `raw-http-authz` | Direct HTTP calls to an external auth service (no SDK) |

## Build

```sh
cargo build --release
```

Produces `find_ac_points`, `find_ac_points_src`, `find_ac_points_js`, and
`find_ac_points_all`. `find_ac_points_llvm` needs a separate opt-in build —
see [Scanning real LLVM IR](#scanning-real-llvm-ir).

## Scanning a MIR dump: `find_ac_points`

```sh
./target/release/find_ac_points --mir <MIR_DUMP> [--datasets <DIR>] [--out <FILE>]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--mir` | yes | — | Path to the RUPTA MIR dump to scan |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions.json` |
| `--out` | no | `ac_matches.json` | Where to write the JSON report |

See [LLM API Finder: Generating a MIR dump](./LLM_API_FINDER.md#generating-a-mir-dump)
for how to produce one.

For a worked example covering every library/category/match strategy, see
`examples/ac_demo_mir.txt` — `tests/fixtures.rs` runs it on every `cargo test`.

## Scanning Rust source directly

`find_ac_points_src` scans `.rs` files directly — no MIR dump needed. Same
catalogue as `find_ac_points`, but matches source *syntax*: a fully-qualified
call is `direct`, method-call syntax is `method`, a call via an aliased
import is `short-name`/`type-method`. It also covers four patterns MIR/LLVM
scanning can't safely see: hand-rolled `impl FromRequestParts`/`FromRequest`
auth guards (`trait-impl`/`extractor-param-usage`), typed header extraction
(`type-usage`), outbound credential headers
(`outbound-credential-header`), and inbound credential-header checks
(`inbound-credential-header`).

```sh
./target/release/find_ac_points_src --src <FILE_OR_DIR> [--datasets <DIR>] [--out <FILE>] [--all-http-calls] [--include-target-dir]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--src` | yes | — | Rust source file or directory to scan |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions.json` |
| `--out` | no | `ac_matches_src.json` | Where to write the JSON report |
| `--all-http-calls` | no | off | Report every `.send(`-shaped call once `reqwest` is referenced |
| `--include-target-dir` | no | off | Also scan `target/` |

```json
{
  "library": "casbin-rs",
  "fn_name": "casbin::CoreApi::enforce",
  "category": "policy-enforcement",
  "match_strategy": "method",
  "callsite": { "file": "src/authz.rs", "function": "check_permission", "line": 10 },
  "parameters": ["(sub, obj, act)"],
  "raw_line": "enforcer.enforce((sub, obj, act)).unwrap_or(false)",
  "verified_via": "general-knowledge"
}
```

For a worked example covering every library/category/match strategy, see
`examples/src/ac_demo.rs` — `tests/fixtures.rs` runs it on every `cargo test`.

`find_ac_points_all --rs-src <DIR>` runs this alongside the MIR/JS scans
under `rust_src_matches`.

## Scanning real LLVM IR

`find_ac_points_llvm` parses an actual LLVM IR module (text `.ll` or
bitcode `.bc`) with the [`llvm-ir`](https://github.com/cdisselkoen/llvm-ir)
crate and walks `call` instructions directly — no RUPTA needed. Reach for
this when you have IR from a build that never goes through RUPTA at all
(`rustc --emit=llvm-ir` directly, or a C/C++ target via clang).

### Why it's opt-in

`llvm-ir` pulls in `llvm-sys`, which needs a **real LLVM install** at build
time (headers, static libs, `llvm-config` on `PATH`), pinned to LLVM 19 —
the newest version `llvm-ir` 0.11.x supports. That's a system requirement
nothing else here has, so it's gated behind a Cargo feature:

```sh
cargo build --release --features llvm-ir-scan
```

Getting LLVM 19 with `llvm-config`:

- **Linux** — your distro's `llvm-19-dev` package (Debian/Ubuntu also needs
  `libpolly-19-dev` and `libzstd-dev` to link).
- **Windows** — the official installer doesn't ship `llvm-config.exe` or
  static libs, so `llvm-sys` can't build against it. Use WSL + a Linux
  `llvm-19-dev` package, or build LLVM 19 from source.
- **macOS** — `brew install llvm@19`; if not auto-discovered, set
  `LLVM_SYS_191_PREFIX=$(brew --prefix llvm@19)` (it's keg-only).

On a different LLVM major version, change `features = ["llvm-19"]` to the
matching `llvm-N` in `Cargo.toml` (`llvm-ir` 0.11 supports `llvm-9` through
`llvm-19`). Only one can be active at a time.

### Usage

```sh
./target/release/find_ac_points_llvm --ir <MODULE.ll|MODULE.bc> [--datasets <DIR>] [--out-dir <DIR>]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--ir` | yes | — | LLVM IR module: text (`.ll`) or bitcode (`.bc`) |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions.json` |
| `--out-dir` | no | `ll_parser/signatures` | Base directory for the JSON report(s) |

Matches are grouped by category and written one file per category actually
matched: `<out-dir>/<category>/<ir-file-stem>.json` (e.g.
`ll_parser/signatures/authentication/ac_demo_llvm.json`).

```json
{
  "library": "jsonwebtoken",
  "fn_name": "jsonwebtoken::decode",
  "category": "authentication",
  "match_strategy": "direct",
  "callsite": { "function": "my_app::verify_token", "block": "%bb0", "instruction_index": 3, "file": "src/main.rs", "line": 42 },
  "mangled_name": "_ZN...",
  "demangled_name": "jsonwebtoken::decode",
  "verified_via": "general-knowledge",
  "return_type": "ptr",
  "parameter_type": ["ptr", "ptr", "ptr"]
}
```

`return_type`/`parameter_type` are the callee's *actual* IR-level types
(ground truth from the compiler), not the catalogue's Rust-level type
strings — don't expect `Result<TokenData<Claims>, Error>` here, Rust
generally lowers that to a bare `ptr`. `callsite.file`/`.line` only appear
when the module carries debug info; otherwise you get block name +
instruction index. `find_ac_points_llvm` never sets `ac_hint` (see [Known
blind spots](#known-blind-spots)).

For a worked example — real `rustc --emit=llvm-ir` output — see
`examples/ac_demo_llvm.ll`. `tests/fixtures.rs` runs it whenever `cargo
test` is run with `--features llvm-ir-scan`.

### Generating an LLVM IR module

```sh
# From a Rust crate:
rustc --edition 2021 --crate-type lib --emit=llvm-ir -o out.ll src/lib.rs
# or via cargo, for a whole crate:
RUSTFLAGS="--emit=llvm-ir" cargo build --release   # .ll lands under target/release/deps/

# From C/C++, with clang:
clang -S -emit-llvm -o out.ll src/main.c
```

Add `-g` to carry source file/line debug info into the IR.

### Regenerating `examples/ac_demo_llvm.ll`

A *current* `rustc` bundles a newer LLVM than this repo's `llvm-19` pin, so
regenerating this fixture needs an older `rustc` whose bundled LLVM
actually matches. The repo's `rust-toolchain.toml` pins `1.86.0` for exactly
this reason (`1.82.0`–`1.86.0` all bundle LLVM 19.1.x; `1.87.0` jumps to
LLVM 20) — running `rustc`/`cargo` from within the repo tree picks it up
automatically, no `+1.86.0` override needed:

```sh
cd examples/src/ac_demo_llvm && mkdir -p .build
rustc --edition 2021 --crate-type lib --crate-name jsonwebtoken -o .build/libjsonwebtoken.rlib jsonwebtoken.rs
rustc --edition 2021 --crate-type lib --crate-name bcrypt       -o .build/libbcrypt.rlib bcrypt.rs
rustc --edition 2021 --crate-type lib --crate-name casbin       -o .build/libcasbin.rlib casbin.rs
rustc --edition 2021 --crate-type lib --crate-name ac_demo_llvm \
  --extern jsonwebtoken=.build/libjsonwebtoken.rlib \
  --extern bcrypt=.build/libbcrypt.rlib --extern casbin=.build/libcasbin.rlib \
  --emit=llvm-ir -o ../../ac_demo_llvm.ll my_app.rs
```

If you're regenerating from outside the repo tree (no `rust-toolchain.toml`
in scope), add `+1.86.0` back to each `rustc` invocation, or confirm your
default `rustc` already bundles LLVM 19 first (check `rustc -vV`).

`find_ac_points_all --llvm-ir <MODULE.ll>` runs this scan alongside the
other three, merged into `llvm_matches`.

## JSON output (MIR scan)

```json
{
  "library": "jsonwebtoken",
  "fn_name": "jsonwebtoken::decode",
  "category": "authentication",
  "match_strategy": "direct",
  "callsite": { "func_id": "FuncId(4)", "function": "my_app::verify_token", "basic_block": "bb0", "line": 812 },
  "raw_line": "_4 = jsonwebtoken::decode::<Claims>(move _1, move _2, move _3) -> [return: bb1, unwind continue];",
  "verified_via": "general-knowledge"
}
```

- `category` — `authentication` | `authorization` | `policy-enforcement` | `raw-http`
- `verified_via` — `general-knowledge` | `docs.rs` | `manual` | `ambient` |
  `unspecified` — how trustworthy this catalogue entry is
- `ac_hint` — present only on `raw-http-authz` matches: a best-effort guess
  at which auth service is being called, from a known REST path suffix
  (`/introspect` → OAuth2 introspection, `/v1/data/` → OPA,
  `/protocol/openid-connect/token` → Keycloak, ...) seen nearby. Absent
  doesn't mean the call isn't access-control-related, just that no known
  suffix was nearby.

## Adding a new library

Edit `datasets/ac_functions.json` — no rebuild needed:

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

Works just as well for a target's own in-house authz function as for a
third-party crate. Add `"kind": "attribute"` to catalogue a proc-macro
attribute guard instead of a call — only `find_ac_points_src` looks for
those (attributes expand away before MIR/LLVM codegen).

## Known blind spots

- **Attribute macros** — expand away before MIR/LLVM IR is emitted, so only
  `find_ac_points_src` can see them, and only for crates catalogued with
  `"kind": "attribute"` (currently just actix-web-grants).
- **Trait-object/generic dispatch** — a call resolved only at
  monomorphization can appear under a different symbol shape than
  catalogued; `short-name` matching covers common cases, not all.
  `find_ac_points_llvm` additionally can't see indirect calls (function
  pointers, vtable dispatch) at all — no static symbol to match.
- **Hand-rolled auth guards in warp** — not catalogued yet (only axum/
  actix-web extractor patterns are). A warp app enforcing auth purely
  through a custom `Filter` combinator will under-report.
- **`find_ac_points_llvm` has no `ac_hint`** — reconstructing nearby string
  literals from LLVM IR means resolving `getelementptr` chains into
  constant globals, not implemented yet; `raw-http-authz` matches from it
  always have `ac_hint: null`.
- **Cross-crate method-name collisions in `find_ac_points_src`** — two
  different catalogued crates imported in the same file that happen to
  share a method name (e.g. two different `.token(...)` methods) both get
  reported on the same call site — text matching can't resolve the
  receiver's real type.
- **`http-auth-header-dynamic` is a whole-file heuristic** — a `.header(name, value)`
  call with a variable header name is gated on an auth-flavored word
  appearing *anywhere in the file*, not near the call, so it's the
  lowest-precision strategy here. Every match says "verify manually" in its
  `ac_hint`.

## Troubleshooting

Same as [`find_llm_calls`'s troubleshooting section](./LLM_API_FINDER.md#troubleshooting) —
datasets-path, RUPTA toolchain pinning, and match-strategy caveats all apply here too.
