# AC (Access Control) Finder (JS/TS)

Companion to [`find_ac_points`](./AC_FINDER.md). Scans JavaScript/TypeScript
**source text** directly — no MIR/RUPTA step — for auth middleware, guard
decorators, RBAC/ABAC checks, and raw HTTP calls to an external auth
service.

## Supported libraries

| Library | Packages | Notes |
|---|---|---|
| `passport` | `passport` | `authenticate`/`authorize` middleware |
| `jsonwebtoken` | `jsonwebtoken` | JWT verification |
| `express-jwt` | `express-jwt` | JWT auth middleware factory |
| `nestjs-authz` | `@nestjs/common`, `@nestjs/passport`, `@nestjs/core` | `@UseGuards`, `@Roles`, `CanActivate`, `SetMetadata` |
| `casl` | `@casl/ability` | `can`/`cannot` permission checks |
| `casbin-node` | `casbin` | `enforce`/`enforceSync` |
| `next-auth` | `next-auth`, `@auth/core` | `getServerSession`, `auth()` |
| `firebase-admin-auth` | `firebase-admin` | `verifyIdToken`, `checkRevoked` |
| `auth0` | `express-openid-connect`, `@auth0/nextjs-auth0` | `requiresAuth`, `withApiAuthRequired`, `getSession` |
| `connect-ensure-login` | `connect-ensure-login` | `ensureLoggedIn`/`ensureLoggedOut` |
| `generic-authz-checks` | — | in-house helpers (`requireRole`, `hasPermission`, ...), always `call-only` |
| `raw-http-authz` | — | `fetch`/`axios`/`http(s).request`, reported when a known AC path is nearby |

These come from general knowledge of each package's API shape and haven't
been re-verified against current docs — spot-check against `package.json`
before trusting a result, especially `generic-authz-checks`.

## Build

```sh
cargo build --release
```

Produces `find_ac_points_js` in `target/release/`.

## Quick example

```sh
./target/release/find_ac_points_js --src path/to/src
```

```
Found 5 access-control call site(s) in path/to/src:

  Found passport [authentication] call (passport.authenticate, authentication middleware) at path/to/src/routes.ts:5 [call+import]
  Found jsonwebtoken [authentication] call (jwt.verify, JWT verification) at path/to/src/routes.ts:6 [call+import]
  Found generic-authz-checks [authorization] call (requireRole, custom role guard (no SDK)) at path/to/src/routes.ts:7 [call-only]
  Found nestjs-authz [authorization] call (UseGuards, route/controller guard decorator) at path/to/src/admin.controller.ts:11 [call+import]
  Found raw-http-authz [raw-http] call (fetch, raw HTTP call to an access-control service) at path/to/src/client.ts:15 [http+path-hint]
    ac hint: OAuth2 token introspection (RFC 7662)
```

A JSON report is written to `ac_matches_js.json` by default. For a worked
example covering every library/category/strategy, see
`examples/src/ac_demo_js.ts` — `tests/fixtures.rs` runs it on every `cargo test`.

## Usage

```sh
./target/release/find_ac_points_js --src <PATH> [--datasets <DIR>] [--out <FILE>] [--all-http-calls] [--include-node-modules]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--src` | yes | — | JS/TS source file or directory to scan |
| `--datasets` | no | `datasets/` | Folder containing `ac_functions_js.json` |
| `--out` | no | `ac_matches_js.json` | Where to write the JSON report |
| `--all-http-calls` | no | off | Report every `fetch`/`axios`/`http(s).request` call, even with no known AC path nearby |
| `--include-node-modules` | no | off | Also scan `node_modules` |

Walks `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs`, skipping `.git` and (by
default) `node_modules`.

## Match strategies

- `call+import` — call shape matched and the file imports the package. High confidence.
- `call-only` — call shape matched, no confirming import (always true for `generic-authz-checks`).
- `http+path-hint` — a `fetch`/`axios`/`http(s).request` call with a known AC REST path nearby.
- `http-call-only` — same call, no known path nearby — only reported with `--all-http-calls`.
- `reference` / `reference+import` — a known pattern passed **by reference** (not invoked) into an Express-style route/mount call, e.g. `router.get("/admin", requireAuth, handler)`.
- `reference+alias` / `reference+alias+import` — same, but the argument is a local variable aliasing a matched pattern, e.g. `const guard = passport.authenticate(...); router.get("/admin", guard, handler)`.

Alias resolution is intentionally narrow: single-hop only, file-scoped, no
cross-file resolution, last declaration wins on reassignment. If a codebase
leans on multi-hop aliasing or re-exports, expect some under-counting.

## Relationship to `find_ac_points`

Both tools write structurally similar JSON. `find_ac_points_all` runs the
Rust MIR scan, Rust source scan, JS/TS scan, and (with
`--features llvm-ir-scan`) the LLVM-IR scan, merging into one report:

```sh
./target/release/find_ac_points_all \
    --mir /tmp/my_program_mir.txt \
    --rs-src path/to/backend/src \
    --src path/to/frontend/src \
    --llvm-ir path/to/module.ll \
    --out ac_matches_all.json
```

Any of `--mir`/`--rs-src`/`--src`/`--llvm-ir` may be omitted (at least one
required). `--llvm-ir` needs a binary built with `--features llvm-ir-scan`
— see [`AC_FINDER.md`](./AC_FINDER.md#scanning-real-llvm-ir).

## Known blind spots

- **In-house guards sharing a catalogue pattern's name** — a `function
  requireRole(...) { ... }` *declaration* is filtered out (not mistaken for
  a call), but a class/object method-shorthand declaration
  (`class Guard { requireRole(role) {...} }`) is textually indistinguishable
  from a call and will still be reported.
- **Locally re-exported wrappers around a generic-name SDK call** — e.g.
  Auth.js v5's recommended idiom (`export { auth as middleware } from
  "auth"`) makes every downstream `import { auth } from "@/auth"` call site
  fail the package-import gate, since the gate checks the module specifier,
  not what the name resolves to. Cataloguing the constructor call itself
  (`NextAuth(...)`) guarantees the definition site isn't invisible, but
  doesn't recover the downstream call sites.

## Troubleshooting

Same shape of issues as [`find_llm_calls_js`](./LLM_API_FINDER_JS.md#troubleshooting):
datasets-path errors, dynamically-dispatched or re-exported wrappers that
text matching can't see through, and `--all-http-calls` producing noise if
you don't actually want unhinted HTTP calls reported.
