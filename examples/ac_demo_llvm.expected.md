# Expected results: examples/ac_demo_llvm.ll

> Verified by an actual `cargo build --release --features llvm-ir-scan` run
> against LLVM 18.1.8 (Ubuntu's `llvm-18-dev`/`libpolly-18-dev`/`libzstd-dev`
> packages, via WSL, since the plain Windows LLVM installer ships no
> `llvm-config`) — the terminal and JSON output below are copy-pasted from
> that run, not hand-traced.

`examples/ac_demo_llvm.ll` is real `rustc --emit=llvm-ir` output (not
hand-written), generated from the four small Rust source files in
`examples/src/ac_demo_llvm/`:

- `jsonwebtoken.rs`, `bcrypt.rs`, `casbin.rs` — minimal stand-ins for those
  crates' public surface, each compiled as its own crate (named
  `jsonwebtoken`/`bcrypt`/`casbin`) so real Rust mangling gives call sites
  the same paths the catalogue expects (`jsonwebtoken::decode`, not
  `ac_demo_llvm::jsonwebtoken::decode`).
- `my_app.rs` — the "application" crate: calls into all three, plus one
  unrelated `format!` call that must not be reported.

## Reproducing the build

`rustc`'s bundled LLVM version has to match (or at least be understood by)
the `llvm-ir` crate's pinned parser version — this repo is pinned to LLVM 18
(see [`AC_FINDER.md`](../src/AC_FINDER.md#retargeting-a-different-llvm-version)),
but a *current* `rustc` bundles a much newer LLVM (22.1.6 as of this
writing) whose IR text isn't parseable by an LLVM-18-vintage parser — it
uses newer instruction-flag syntax (e.g. `trunc nuw`) that didn't exist yet
in LLVM 18. Generating this fixture needed an older `rustc` whose bundled
LLVM actually matches:

```sh
rustup toolchain install 1.78.0   # bundles LLVM 18.1.2 -- matches our pin
cd examples/src/ac_demo_llvm
mkdir -p .build
rustc +1.78.0 --edition 2021 --crate-type lib --crate-name jsonwebtoken -o .build/libjsonwebtoken.rlib jsonwebtoken.rs
rustc +1.78.0 --edition 2021 --crate-type lib --crate-name bcrypt       -o .build/libbcrypt.rlib bcrypt.rs
rustc +1.78.0 --edition 2021 --crate-type lib --crate-name casbin       -o .build/libcasbin.rlib casbin.rs
rustc +1.78.0 --edition 2021 --crate-type lib --crate-name ac_demo_llvm \
  --extern jsonwebtoken=.build/libjsonwebtoken.rlib \
  --extern bcrypt=.build/libbcrypt.rlib \
  --extern casbin=.build/libcasbin.rlib \
  --emit=llvm-ir -o ../../ac_demo_llvm.ll \
  my_app.rs
```

If your default `rustc` already bundles LLVM 18 (check `rustc -vV`), you can
drop the `+1.78.0` toolchain overrides.

Then scan it:

```sh
cargo build --release --features llvm-ir-scan
./target/release/find_ac_points_llvm --ir examples/ac_demo_llvm.ll
```

## Terminal output

```
[find_ac_points_llvm] loaded 25 signatures from datasets/ac_functions.json
Found 3 access-control call site(s) in examples/ac_demo_llvm.ll:

  Found jsonwebtoken [authentication] call (jsonwebtoken::decode) in ac_demo_llvm::verify_token at %start / instr #3 [direct]
  Found bcrypt [authentication] call (bcrypt::verify) in ac_demo_llvm::check_password at %start / instr #0 [direct]
  Found casbin-rs [policy-enforcement] call (casbin::CoreApi::enforce) in ac_demo_llvm::check_permission at %start / instr #0 [angle-bracket]
[find_ac_points_llvm] JSON written to ac_matches_llvm.json
```

`ac_demo_llvm::greet` (the `format!("hello, {name}")` function) is correctly
absent — it's a real, successfully-demangled call chain (`Arguments::new_v1`,
`alloc::fmt::format`, ...) that just doesn't match any catalogue entry.

## JSON output

```json
{
  "ir_file": "examples/ac_demo_llvm.ll",
  "matches": [
    {
      "callsite": {
        "block": "%start",
        "function": "ac_demo_llvm::verify_token",
        "instruction_index": 3
      },
      "category": "authentication",
      "demangled_name": "jsonwebtoken::decode",
      "fn_name": "jsonwebtoken::decode",
      "library": "jsonwebtoken",
      "mangled_name": "_ZN12jsonwebtoken6decode17hdd5a20d74b58ee6dE",
      "match_strategy": "direct"
    },
    {
      "callsite": {
        "block": "%start",
        "function": "ac_demo_llvm::check_password",
        "instruction_index": 0
      },
      "category": "authentication",
      "demangled_name": "bcrypt::verify",
      "fn_name": "bcrypt::verify",
      "library": "bcrypt",
      "mangled_name": "_ZN6bcrypt6verify17hfa047a641201e7aaE",
      "match_strategy": "direct"
    },
    {
      "callsite": {
        "block": "%start",
        "function": "ac_demo_llvm::check_permission",
        "instruction_index": 0
      },
      "category": "policy-enforcement",
      "demangled_name": "<casbin::Enforcer as casbin::CoreApi>::enforce",
      "fn_name": "casbin::CoreApi::enforce",
      "library": "casbin-rs",
      "mangled_name": "_ZN52_$LT$casbin..Enforcer$u20$as$u20$casbin..CoreApi$GT$7enforce17h881d5c680406215aE",
      "match_strategy": "angle-bracket"
    }
  ],
  "signatures_loaded": 25,
  "total_matches": 3
}
```

There's no `callsite.file`/`callsite.line` on any match — `rustc
+1.78.0 --emit=llvm-ir` without `-g` carries no debug info, so
`find_ac_points_llvm` falls back to `block` + `instruction_index` as the
locator (see `AcLlvmCallSite` in `src/ac_finder_llvm.rs`). Compiling with
`-g` would carry real source locations instead.

## What this shows

- **`direct` match strategy** on real, parsed `call` instructions (not text
  regex) — `jsonwebtoken::decode` and `bcrypt::verify` are both exact
  demangled-path matches, the LLVM-IR analogue of `ac_finder`/
  `ac_finder_rs_src`'s `direct` strategy.
- **`angle-bracket` match strategy** on a *real compiled trait-impl call
  site* — `<casbin::Enforcer as casbin::CoreApi>::enforce`, mangled as
  `_ZN52_$LT$casbin..Enforcer$u20$as$u20$casbin..CoreApi$GT$7enforce17h...E`.
  This is exactly the case the original hand-authored version of this
  fixture explicitly avoided, because hand-mangling a realistic trait-impl
  symbol correctly (v0 or the `$LT$...$GT$`-escaped legacy form) isn't safe
  to eyeball without a compiler. Real `rustc` output settled it instead —
  and see "A bug this exposed" below for what it caught.
- **Demangling round-trip on both sides of a call** — `mangled_name`/
  `demangled_name` on the callee, and a demangled `callsite.function` for
  the caller (`ac_demo_llvm::verify_token`, not
  `_ZN12ac_demo_llvm12verify_token17h...E`).
- **No false positive on an unrelated, successfully-demangled call chain**
  — `ac_demo_llvm::greet`'s `format!` call chain demangles fine but matches
  no catalogue entry, and is correctly not reported.

## A bug this exposed

Building this fixture from real compiler output (rather than trusting
hand-written IR with artificially hash-free symbols) caught a real bug:
`rustc_demangle::demangle(...).to_string()` uses the *default* `Display`
impl, which — counter-intuitively — **shows** the trailing `::h<hash>`
legacy-mangling suffix rustc appends to every symbol (e.g.
`_ZN12jsonwebtoken6decode17hdd5a20d74b58ee6dE` demangles by default to
`jsonwebtoken::decode::hdd5a20d74b58ee6d`, not `jsonwebtoken::decode`).
Only the *alternate* form (`format!("{:#}", ...)`) hides it. The scanner
originally used the default form, so it matched nothing on any real
rustc-produced symbol with a hash suffix — every hand-written unit test
happened to use hash-free symbols (mirroring `rustc_demangle`'s own
hash-free doctest example), which never exercised this path. Fixed in
`src/ac_finder_llvm.rs`, with real hash-bearing symbols (captured from this
exact build) now used in `end_to_end_scan_finds_jsonwebtoken_decode` and
`end_to_end_scan_finds_casbin_trait_impl_call` as a regression guard.

## What this still does not exercise

- **`short-name` match strategy** — same regex logic as `direct`/
  `angle-bracket`, only reachable in practice when a catalogue signature's
  full path doesn't match but its last two segments do (e.g. a re-exported
  alias). Not forced here to keep the demo crates realistic; see the
  `detects_direct_call_by_demangled_name` /
  `detects_trait_method_via_angle_bracket_strategy` unit tests in
  `src/ac_finder_llvm.rs` for direct strategy-logic coverage instead.
- **`ac_hint` for `raw-http-authz` matches** — always `None` from this
  scanner today; see the `ac_hint` doc comment on `AcLlvmMatch` in
  `src/ac_finder_llvm.rs` and "Known blind spots" in
  `../src/AC_FINDER.md`.
- **Indirect calls** (function pointers, `dyn Trait` dispatch) — the callee
  would be a `LocalOperand`, not a `GlobalReference`, so there's no static
  symbol to demangle and match; same blind spot as trait-object dispatch in
  the MIR/source scanners.
- **Debug info** (`callsite.file`/`callsite.line`) — this fixture is
  compiled without `-g`; see above.
