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
| `actix-web-grants` | Role/permission-based authorization middleware for actix-web |
| `actix-identity` | Session identity extraction for actix-web |
| `axum-login` | Session-based authentication and authorization backends for axum |
| `tower-http-auth` | `ValidateRequestHeaderLayer`/`AsyncRequireAuthorizationLayer` tower middleware |
| `jsonwebtoken` | JWT signature/claims verification (`decode`, `decode_header`) |
| `casbin-rs` | Casbin policy enforcement (`enforce`, `enforce_mut`) |
| `oso` | Oso policy engine (`is_allowed`) |
| `biscuit-auth` | Biscuit token authorization (`Authorizer::authorize`) |
| `ldap3` | LDAP bind/authentication (`LdapConn::simple_bind`, `Ldap::simple_bind`) |
| `oauth2` | OAuth2 authorization-code token exchange (`Client::exchange_code`) |
| `bcrypt` | bcrypt password hash verification (`bcrypt::verify`) |
| `argon2` | Argon2 password hash verification (`PasswordVerifier::verify_password`) |
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

For a worked example exercising every library, category, and match strategy
(`direct`, `angle-bracket`, `short-name`) in one file, see
`examples/ac_demo_mir.txt` — hand-written text in RUPTA's MIR-dump shape
rather than a real RUPTA run, the same role `examples/src/ac_demo.rs` plays
for `find_ac_points_src`. `tests/fixtures.rs` runs it and checks the JSON
output on every `cargo test`.

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
in one file, see `examples/src/ac_demo.rs`. `tests/fixtures.rs` runs it and
checks the JSON output on every `cargo test`.

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
instead of a MIR text line. Each match in `ac_matches_llvm.json` looks like:

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
  "demangled_name": "jsonwebtoken::decode"
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
covers the common cases but isn't exhaustive. `find_ac_points_llvm` has the
equivalent gap for indirect calls (function pointers, vtable dispatch): the
callee is a local SSA value rather than a `GlobalReference`, so there's no
static symbol to demangle and match against the catalogue.

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
