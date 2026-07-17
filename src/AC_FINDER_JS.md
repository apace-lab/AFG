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

This closes the common case, but a real blind spot remains: an **aliased**
reference —

```js
const guard = passport.authenticate("jwt");
router.get("/admin", guard, handler);
```

— can't be resolved without data-flow analysis. `guard` doesn't textually
match any cataloged pattern, so this scanner (which only ever does text
matching, never binds identifiers to their definitions) has no way to know it
came from `passport.authenticate`. If a codebase leans on this style, expect
under-counting — read the route table by hand as a supplement, don't treat a
zero-match result as proof a route is unguarded.

## Relationship to `find_ac_points`

Both tools write structurally similar JSON (`library`, `category`, a call
identifier, `match_strategy`, a `callsite`, `raw_line`, optional `ac_hint`).
`find_ac_points_all` runs the Rust MIR scan, then the Rust source scan, then
the JS/TS source scan, and writes one merged report with `rust_matches` /
`rust_src_matches` / `js_matches` / `total_matches`, exactly like
`find_llm_calls_all`:

```sh
./target/release/find_ac_points_all \
    --mir /tmp/my_program_mir.txt \
    --rs-src path/to/backend/src \
    --src path/to/frontend/src \
    --out ac_matches_all.json
```

Any of `--mir`, `--rs-src`, or `--src` may be omitted to skip that scan (at
least one is required).

## Troubleshooting

Same shape of issues as [`find_llm_calls_js`](./LLM_API_FINDER_JS.md#troubleshooting):
datasets-path errors, dynamically-dispatched or re-exported wrappers that text
matching can't see through, and `--all-http-calls` producing noise if you
don't actually want unhinted HTTP calls reported.
