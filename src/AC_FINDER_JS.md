# AC (Access Control) Finder (JS/TS)

Companion to [`find_ac_points`](./AC_FINDER.md), which scans a Rust program's
RUPTA MIR dump. This tool scans JavaScript/TypeScript **source text**
directly — there is no MIR/RUPTA step — for access-control call sites: auth
middleware, guard decorators, RBAC/ABAC permission checks, and raw HTTP calls
to an external auth service. It is the AC-finder counterpart to
[`find_llm_calls_js`](./LLM_API_FINDER_JS.md) and reuses the same
text-scanning design.

## What it does

Given a JS/TS source file or directory, `find_ac_points_js` tells you:

- **Which mechanism** the call shape matches (e.g. `passport`, `@nestjs/common` guards, an in-house `requireRole()` helper)
- **Which category** it falls under — `authentication`, `authorization`, `policy-enforcement`, `session`, or `raw-http`
- **Whether an import confirms it** — a distinctive multi-segment call like
  `passport.authenticate` is reported on its own; a generic one-word call
  like `can(` or `enforce(` is only reported when the file also imports the
  matching SDK package
- **Where exactly** — file and line number
- **Access-control service guess for raw `fetch`/`axios` calls**, from a
  known REST path suffix found in a nearby string literal (OAuth2, OIDC,
  Keycloak, OPA, Vault — see `src/ac_hints.rs`)

Results are printed to the terminal and saved as JSON, in the same shape as
`find_ac_points`'s output.

## Supported libraries

| Library | Packages | Notes |
|---|---|---|
| `passport` | `passport` | `authenticate`/`authorize` middleware |
| `jsonwebtoken` | `jsonwebtoken` | JWT verification |
| `express-jwt` | `express-jwt` | JWT auth middleware factory |
| `nestjs-authz` | `@nestjs/common`, `@nestjs/passport`, `@nestjs/core` | `@UseGuards`, `@Roles`, `CanActivate`, `SetMetadata` |
| `casl` | `@casl/ability` | `can`/`cannot` permission checks, ability definitions |
| `casbin-node` | `casbin` | `enforce`/`enforceSync` policy checks |
| `next-auth` | `next-auth`, `@auth/core` | Session retrieval (`getServerSession`, `auth()`) |
| `firebase-admin-auth` | `firebase-admin` | `verifyIdToken`, `checkRevoked` |
| `auth0` | `express-openid-connect`, `@auth0/nextjs-auth0` | `requiresAuth`, `withApiAuthRequired`, `getSession` |
| `connect-ensure-login` | `connect-ensure-login` | `ensureLoggedIn`/`ensureLoggedOut` |
| `generic-authz-checks` | — | Hand-rolled in-house helpers (`requireRole`, `hasPermission`, `isAdmin`, etc.) — no package to confirm against, always reported as `call-only` |
| `raw-http-authz` | — | `fetch`/`axios`/`http(s).request` calls, reported when a known access-control REST path is found nearby |

These signatures come from general knowledge of each package's public API
shape and have **not** been independently re-verified against current
published docs. Spot-check against the target's actual installed version
(`package.json`) before trusting a result — especially `generic-authz-checks`,
which is a bare pattern match with no SDK to confirm it against and will hit
unrelated code that happens to share a common function name.

## Build

```sh
cargo build --release
```

Produces `find_ac_points_js` in `target/release/` alongside the LLM finder
binaries.

## Quick example

```sh
./target/release/find_ac_points_js --src path/to/src
```

Output:

```
Found 5 access-control call site(s) in path/to/src:

  Found passport [authentication] call (passport.authenticate, authentication middleware) at path/to/src/routes.ts:5 [call+import]
  Found jsonwebtoken [authentication] call (jwt.verify, JWT verification) at path/to/src/routes.ts:6 [call+import]
  Found generic-authz-checks [authorization] call (requireRole, custom role guard (no SDK)) at path/to/src/routes.ts:7 [call-only]
  Found nestjs-authz [authorization] call (UseGuards, route/controller guard decorator) at path/to/src/admin.controller.ts:11 [call+import]
  Found raw-http-authz [raw-http] call (fetch, raw HTTP call to an access-control service) at path/to/src/client.ts:15 [http+path-hint]
    ac hint: OAuth2 token introspection (RFC 7662)
```

A JSON report is written to `ac_matches_js.json` by default.

For a worked example exercising every library, category, and match strategy
in one file, see `examples/src/ac_demo_js.ts`. `tests/fixtures.rs` runs it
and checks the JSON output on every `cargo test`.

## Usage

```sh
./target/release/find_ac_points_js --src <PATH> [--datasets <DIR>] [--out <FILE>] [--all-http-calls] [--include-node-modules]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--src` | yes | — | JS/TS source file or directory to scan |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions_js.json` |
| `--out` | no | `ac_matches_js.json` | Where to write the JSON report |
| `--all-http-calls` | no | off | Report every `fetch`/`axios`/`http(s).request` call, even without a known access-control path nearby |
| `--include-node-modules` | no | off | Also scan `node_modules` |

Directory scans walk `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` files and
skip `.git` and (by default) `node_modules`.

## Match strategies

- `call+import` — a call-shape pattern matched, and the file also imports the
  package it belongs to. High confidence.
- `call-only` — the call-shape pattern matched but no confirming import was
  found. All `generic-authz-checks` entries are always `call-only` since
  they're in-house code with no package to check against.
- `http+path-hint` — a `fetch`/`axios`/`http(s).request` call with a known
  access-control REST path suffix found nearby.
- `http-call-only` — same call, but no known path found nearby. Only
  reported with `--all-http-calls`.
- `reference+import` — a known AC pattern was passed **by reference** (not
  invoked) as an argument to an Express-style route/mount call, and the file
  also imports the package it belongs to.
- `reference` — same, but with no confirming import (or the pattern has no
  associated package, e.g. `generic-authz-checks`).
- `reference+alias+import` — the argument wasn't itself a known pattern name,
  but is a local `const`/`let`/`var` alias for one (`const guard =
  passport.authenticate(...)`), and the file imports the package it belongs
  to. See [Middleware passed by reference](#middleware-passed-by-reference).
- `reference+alias` — same, but with no confirming import (or the aliased
  pattern has no associated package).

## Middleware passed by reference

Express-style routes commonly pass a guard **by reference**, not as a call:

```js
router.get("/admin", requireAuth, handler);
```

Here `requireAuth` is a bare identifier — nothing in the source looks like
`requireAuth(`. A separate detection pass (independent of the call-shape
matchers above) handles this case specifically: it finds Express-ish
route/mount calls (`app.get(...)`, `router.use(...)`, an identifier ending in
`app`/`App`/`router`/`Router`, or `route`/`server`), parses the argument list
with a small paren/bracket/string-aware scanner, and reports any argument
that is *exactly* a known AC pattern — including one level of `[...]`
middleware-array unwrapping (`router.get("/x", [auth, isAdmin], handler)`).
The higher-order factory form (`requireRole("admin")`) is still caught by the
ordinary call-shape matcher, not this one, so it isn't double-reported.

This closes the common case, and a common **aliased** variant is also
resolved —

```js
const guard = passport.authenticate("jwt");
router.get("/admin", guard, handler);
```

`guard` doesn't textually match any cataloged pattern on its own, but a
separate single-hop alias pass scans the whole file for `const`/`let`/`var
IDENT = <expr>;` declarations, checks whether `<expr>` matches a call-shape
pattern (same import-confirmation gate as an ordinary call), and records
`IDENT` against the signature it matched. The bare-reference pass above then
resolves through that table when an argument isn't a direct pattern-name
match, reporting it as `reference+alias`/`reference+alias+import` (see [Match
strategies](#match-strategies)). `guard` in the example above is reported as
a `passport` reference, resolved via the `guard` alias.

This is still text matching, not real data-flow analysis, so it's
deliberately narrow:

- **Single hop only** — `const a = passport.authenticate(...); const b = a;`
  does not resolve `b`; only the direct alias of the matched expression is
  tracked.
- **File-scoped, not block/function-scoped** — an alias declared anywhere in
  the file is visible everywhere in that file, the same looseness the rest of
  this scanner already has (see `callsite.function` in
  [`find_ac_points_src`](./AC_FINDER.md#scanning-rust-source-directly) for the
  Rust-side equivalent).
- **No cross-file resolution** — an alias declared in one file can't be
  resolved from an `import` of it in another file.
- **No reassignment tracking** — the last matching declaration for a given
  name wins if the same identifier is redeclared with `let`/`var`.

If a codebase leans on patterns this doesn't cover (multi-hop aliasing,
destructured re-exports, aliases built inside a function and passed out),
expect some under-counting — read the route table by hand as a supplement,
don't treat a zero-match result as proof a route is unguarded.

## Relationship to `find_ac_points`

Both tools write structurally similar JSON (`library`, `category`, a call
identifier, `match_strategy`, a `callsite`, `raw_line`, optional `ac_hint`).
`find_ac_points_all` runs the Rust MIR scan, the Rust source scan, the JS/TS
source scan, and (with `--features llvm-ir-scan`) the real-LLVM-IR scan, and
writes one merged report with `rust_matches` / `rust_src_matches` /
`js_matches` / `llvm_matches` / `total_matches`, exactly like
`find_llm_calls_all`:

```sh
./target/release/find_ac_points_all \
    --mir /tmp/my_program_mir.txt \
    --rs-src path/to/backend/src \
    --src path/to/frontend/src \
    --llvm-ir path/to/module.ll \
    --out ac_matches_all.json
```

Any of `--mir`, `--rs-src`, `--src`, or `--llvm-ir` may be omitted to skip
that scan (at least one is required). `--llvm-ir` only works on a binary
built with `--features llvm-ir-scan` — see
[`AC_FINDER.md`](./AC_FINDER.md#scanning-real-llvm-ir).

## Known blind spots

**A codebase's own in-house guard sharing a catalogue pattern's name** — a
generic pattern like `requireRole`/`hasPermission`/`isAdmin`
(`generic-authz-checks`) is exactly the kind of name a project would pick for
its *own* auth helper, and its declaration —

```ts
function requireRole(role: string) {
  return function (req, res, next) { /* ... */ };
}
```

— textually contains `requireRole(`, identical to a call. This is filtered:
`is_fn_declaration` recognizes the `function`/`async function`/`function*`
keyword immediately preceding the match (mirroring `is_fn_declaration` in
`ac_finder_rs_src.rs` for Rust's `fn` keyword) and skips it. A real call to
that same name elsewhere is still reported normally — see the
`fn_declaration_sharing_a_pattern_name_is_not_a_call` and
`calling_a_pattern_named_after_a_declared_function_is_still_reported` tests.

This only covers the unambiguous `function`-keyword form. **Class/object
method-shorthand declarations remain unfiltered** —

```ts
class Guard {
  requireRole(role) { /* ... */ }   // declaration, not a call
}
```

— is textually indistinguishable from a call (`requireRole(`) without full
parsing, so it will still be reported. Same shape of caveat as the
alias-resolution limits above: expect some over-counting from
method-shorthand declarations named after a generic pattern.

## Troubleshooting

Same shape of issues as [`find_llm_calls_js`](./LLM_API_FINDER_JS.md#troubleshooting):
datasets-path errors, dynamically-dispatched or re-exported wrappers that text
matching can't see through, and `--all-http-calls` producing noise if you
don't actually want unhinted HTTP calls reported.
