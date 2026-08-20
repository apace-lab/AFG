# Verifying the LLM API catalogue against real compiled IR

A teaching note about one session's changes: pinning this repo's Rust
toolchain, and re-verifying every entry in `datasets/llm_api_functions.json`
against *actually compiled* LLVM IR instead of documentation. Written for
someone who wants to understand not just what changed, but why each change
was necessary and what the underlying Rust/LLVM mechanics are. Companion to
`SIGNATURE_CATEGORIES.md`, which covers an earlier pass over the same file
(adding `category`/`request_index`/`prompt_arg_index`/`prompt_role`) — this
note picks up where that one left off.

## The problem this solves

`datasets/llm_api_functions.json` catalogues functions from ~10 Rust LLM SDK
crates (`async-openai`, `ollama-rs`, `clust`, ...) for a downstream
taint-analysis tool (RUPTA). Each entry has fields like `return_type`,
`parameter_type`, and `request_index` that describe a function's *compiled*
shape — specifically, whether the compiler returns its value indirectly
through a hidden pointer argument (see "What `sret` means" below), and which
argument position holds the actual outbound request.

Before this session, those fields were derived from **documentation**
(`verified_via: "docs.rs"`, `"context7:/..."`) — someone read the crate's
public API and wrote down what they expected the compiled signature to look
like. That's a reasonable starting point, but it's a guess about a compiler
implementation detail, and guesses about ABI shape are exactly the kind of
thing that's easy to get subtly wrong (see the `reqwest`/`llm_chain`
findings below — both guesses were wrong in a way no amount of re-reading
the docs would have caught).

The fix: actually compile real code against each real crate, and read the
answer off the real generated IR.

## Part 1: pinning the toolchain

### The LLVM version problem

This repo's `llvm-ir`/`llvm-sys` dependencies are pinned to LLVM **19.x**
(see `Cargo.toml`) — the Rust crate that parses `.ll` IR files understands
LLVM 19's IR grammar specifically. To generate an `.ll` file that this
crate can reliably parse, the `rustc` doing the generating needs to bundle
LLVM 19 as its own code-generation backend too (every `rustc` build embeds
a specific LLVM version internally — that's what actually turns Rust into
machine code, and it's also what `--emit=llvm-ir` dumps mid-pipeline).

Rust bumps its bundled LLVM version every few releases. We checked
empirically:

| rustc | bundled LLVM |
|---|---|
| 1.85.0 | 19.1.7 |
| 1.86.0 | 19.1.7 |
| 1.87.0 | 20.1.1 |
| 1.88.0 – 1.90.0 | 20.1.x |

**1.86.0 is the last version bundling LLVM 19** — one release later and
every `.ll` file generated would be in LLVM 20's dialect, which this repo's
pinned parser isn't guaranteed to handle correctly.

### The fix: `rust-toolchain.toml`

Added to the repo root:

```toml
[toolchain]
channel = "1.86.0"
```

This is a [standard rustup mechanism](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file):
any `rustc`/`cargo` invoked from within this directory tree automatically
uses 1.86.0, with no `+1.86.0` flag needed, no global `rustup default`
change, and no effect on any other project on the machine. It's checked
into git, so anyone who clones the repo gets the same guarantee.

### The collateral fix: `PathBuf::leak()`

Pinning to 1.86.0 immediately broke the build:

```
error[E0658]: use of unstable library feature `os_string_pathbuf_leak`
   --> src\ac_finder.rs:356:64
    |
356 |         Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").leak()
```

Five test-helper functions (one per `*_finder*.rs` module) used
`PathBuf::leak()` — a convenience method that turns an owned `PathBuf` into
a `&'static Path` by intentionally never freeing it (fine for test fixtures,
which live for the process's whole lifetime anyway). That method was only
*stabilized* after 1.86.0, so the pin broke it.

The fix doesn't change behavior at all — it just spells the same operation
the older, always-stable way, using `Box::leak` (stable since Rust 1.0)
instead of the newer `PathBuf`-specific sugar:

```rust
// Before (needs rustc >= ~1.87, unstable on 1.86.0):
Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").leak()

// After (stable on any rustc):
Box::leak(Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets").into_boxed_path())
```

`into_boxed_path()` converts `PathBuf` → `Box<Path>`, and `Box::leak`
converts `Box<Path>` → `&'static mut Path` (which coerces to `&'static
Path` here). Same leaked-forever effect, no new stdlib feature required.

**Lesson for later:** whenever you deliberately pin an older toolchain for
one reason (LLVM version, in this case), be ready for it to reject code
that was written/tested against whatever newer toolchain was previously in
use. Always `cargo clean` after a toolchain switch before trusting the
result — stale incremental-compilation artifacts from the old toolchain can
produce confusing, non-reproducible errors otherwise (this happened once
during this session and looked like a flaky compiler bug until a clean
rebuild made it reproducible).

## Part 2: what "verified via real IR" actually means

### What `sret` means

When a function returns a large or non-trivial value, the compiler often
can't fit it in registers. Instead of returning the value directly, the
*caller* allocates space for it and passes a hidden pointer to that space
as an extra argument — the callee writes its result through that pointer
instead of "returning" anything at the machine-code level. This is called
**struct return**, or `sret`, and it's an extremely common ABI convention
(not Rust-specific — C++ compilers do this too).

Concretely, in the generated IR, an `sret` function looks like this (real
output, from this session's verification of `async_openai::chat::Chat::create`):

```llvm
define internal void @"_ZN12async_openai4chat13Chat$LT$C$GT$6create..."
    (ptr sret([3464 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %request)
```

Notice the function's actual return type is `void` — nothing comes back
through the normal return mechanism. The *real* output goes through
`%_0`, the first parameter, marked `sret`. Everything after it (`%self`,
`%request`) is a normal argument, just shifted one position later than
you'd expect from reading the Rust source.

This matters for the catalogue because RUPTA (the downstream consumer)
needs to know exactly which argument position holds the outbound request
— and if a function uses `sret`, "the 2nd Rust-level argument" and "the
2nd `parameter_type` array index" are off by one. The dataset's convention
is to prepend a literal `"sret"` string to `parameter_type` for functions
that use it, so `request_index` can be a single 0-based number that means
the same thing regardless.

### The mangled name

Every function name in the IR is *mangled* — encoded into a compact,
unambiguous symbol like `_ZN12async_openai4chat13Chat$LT$C$GT$6create17hfdd80ff68be353a8E`.
Reading that by hand is painful, so `rustc` also prints a **demangled**
comment above every `define`/`call`/`invoke` site, which is what actually
made this verification tractable:

```llvm
; async_openai::chat::Chat<C>::create
define internal void @"_ZN12async_openai4chat13Chat$LT$C$GT$6create..."(...)
```

Grepping for `; async_openai::` (etc.) in a generated `.ll` file is how
each SDK's real call sites were located.

### The methodology

For each of the 9 remaining SDKs (`async-openai` had already been done in
an earlier pass), the same recipe:

1. **Look up the crate's real current docs** (docs.rs/crates.io) — the
   dataset had already gone stale once before (see `SIGNATURE_CATEGORIES.md`),
   so fn_names/paths needed re-confirming, not just types.
2. **Write a tiny scratch crate** (`cargo new --lib`) with the *one* real
   SDK as a dependency, pinned to rustc 1.86.0 via its own
   `rust-toolchain.toml`.
3. **Write plain functions that call the catalogued methods** with
   plausible (not necessarily runnable) arguments — mirroring the existing
   convention in `examples/src/ac_demo_llvm/my_app.rs`. Compiled in debug
   mode (no `--release`/`-O`), so the compiler doesn't inline the call away
   before it can be inspected.
4. **Compile to IR**: `cargo rustc --lib -- --emit=llvm-ir -C debuginfo=0`.
5. **Grep the output** for the target function's demangled comment, and
   read its real signature: is there an `sret`? How many real parameters,
   and in what order?
6. **Report back**, quoting the real IR line as evidence for any correction.

This was parallelized across 8 background agents (roughly one per SDK,
with the two smallest paired up) since each SDK's verification is fully
independent — different crate, different scratch directory, no shared
state until the results get merged back into the one JSON file by hand.

## Part 3: what changed, per SDK

| SDK | Result |
|---|---|
| `async-openai` | 11 of 13 entries confirmed unchanged; 3 already-corrected `fn_name`s (from an earlier pass) reconfirmed against real IR |
| `ollama-rs` | All 6 entries confirmed unchanged |
| `genai` | Both entries confirmed unchanged (verified against 0.3.5 — 0.6.x needs a newer rustc than this repo can use, see below) |
| `reqwest` | 1 confirmed; 1 real correction (`RequestBuilder::send`, async — see "no sret at all" below) |
| `clust` | Both entries: wrong error type name corrected (`ApiError` → `MessagesError`, a wrapper enum) |
| `anthropic-sdk` | Wrong error type name corrected (`AnthropicError` → `anyhow::Error`, since the crate just uses `anyhow` throughout) |
| `misanthropic` | Both entries: wrong success/stream type names corrected (`Response` → `response::Message`, `ResponseStream` → `Stream`) |
| `gemini-rust` | 3 real type-name corrections (`GenerateContentBuilder`→`ContentBuilder`, `GenerateContentResponse`→`GenerationResponse`, `GeminiError`→`ClientError`, etc.); **1 entry removed** — see below |
| `rig-core` | 2 `fn_name` corrections (missing a `request` module segment) |
| `llm-chain` | 1 real ABI correction (`Executor::execute` — see "no sret at all" below); 1 confirmed unchanged |

### A fabricated entry, found and removed

`gemini_rust::Conversation::send_message` doesn't exist. The verifying
agent checked every released version of `gemini-rust` from 1.2.3 through
2.0.0, plus the current `main` branch, and found zero occurrences of a
`Conversation` type or a `send_message` method anywhere in the crate's
source. There's no reasonable "it got renamed" story here — nothing in the
crate's history resembles a multi-turn conversation API under that name.
The entry was deleted rather than corrected, since there was no real
symbol to derive a corrected signature from.

This is exactly the kind of error real-IR verification catches that
documentation-review can't: a plausible-sounding, nicely-shaped JSON entry
that simply doesn't correspond to anything real. It would have silently
never matched any real call site, forever, with no error or warning.

### Two "no `sret` at all" surprises

The dataset's schema note (`sret_convention`) says: prepend `"sret"`
whenever `return_type` is `Result<T, E>`. Two entries broke that rule, in
the *same* way, for a subtler reason than a wrong type name — and both are
worth understanding because the same trap will bite any future addition to
this catalogue.

**`reqwest::RequestBuilder::send`** (the async one). Its documented
signature returns `Result<Response, Error>` — but that's not what the
function you actually *call* returns. `send()` isn't itself declared
`async fn`; it's a plain function that returns `impl Future<Output =
Result<Response, Error>>`. The `Result` only exists once you `.await` that
future. The concrete future type reqwest generates here happens to be
small — 16 bytes — so it's returned in two ordinary registers
(`{ i64, ptr }`), not through an indirect `sret` pointer at all:

```llvm
declare { i64, ptr } @_ZN7reqwest10async_impl7request14RequestBuilder4send(ptr align 8)
```

Only one real parameter (`self`), no `sret`. `parameter_type` was
corrected from `["sret", "self"]` to `["self"]`, and `request_index` from
`1` to `0`.

**`llm_chain::traits::Executor::execute`**. This one's `async_trait`-boxed
— a common pattern for making async methods work in a `dyn Trait` object,
via the `#[async_trait]` macro. That macro rewrites the method to return
`Pin<Box<dyn Future<Output = Result<Output, ExecutorError>> + Send>>`
instead of a native `async fn`. A `Box`ed trait object is a **fat
pointer** — data pointer + vtable pointer, 16 bytes, always returned in a
register pair, never indirectly:

```llvm
declare { ptr, ptr } @"...Executor$GT$7execute..."(ptr align 8, ptr align 8, ptr align 8)
```

Same story: no `sret`, and `request_index` shifted from `3` down to `2`.

**The generalizable lesson** (now written into the dataset's own
`_schema_notes.async_sret_caveat` for future maintainers): whether an
async method gets an `sret` slot depends on *how* it's implemented — a
native `async fn` with a large generated state machine, yes; a plain fn
returning a small `impl Future` or a boxed trait object, no. You cannot
tell which case you're in by reading `return_type` alone. You have to
check real IR.

### And the opposite case: `sret` present, but not because of `Result`

Several confirmed-correct entries (`ollama-rs`, `clust`, `rig-core`,
`misanthropic`) *do* have an `sret` slot — but per the same investigation,
it's not literally because they return `Result<T, E>`. They're native
`async fn`s, and the compiler generates a coroutine/state-machine struct
to represent "this function, paused at its await point." *That* struct
is what's `sret`-returned (it's often hundreds or thousands of bytes —
e.g. 1592 bytes for `clust::Client::create_a_message`) — the `Result`
only exists later, as that state machine's eventual output once
something polls it to completion. The argument *positions* still work out
identically to what the dataset already assumed (the `Result`-based
mental model gets the right answer for the wrong reason), so no entries
needed correcting on this basis — but it's why the schema note now
describes the mechanism precisely rather than the simplified
"Result-shaped things get sret" story.

### Toolchain ceilings hit along the way

Three crates' *latest* published versions couldn't compile under this
repo's LLVM-19-pinned rustc 1.86.0 at all:

- `misanthropic` 1.0.0-alpha.16 uses **let-chains**
  (`if let ... && let ...`), a 2024-edition syntax feature that needs
  rustc ≥ 1.88 to parse, regardless of what edition the *consuming* crate
  declares.
- `rig-core` 0.17.1 through the latest 0.41.0 hit the same let-chains wall.
- `genai` 0.4.0 through the latest 0.6.5, same wall.

In each case, the verifying agent fell back to the newest version that
*does* compile under 1.86.0 (`rig-core` 0.16.0, `genai` 0.3.5,
`misanthropic` compiled instead under 1.88.0 as a documented exception),
and — where possible — cross-checked via source diff that the specific
signatures being catalogued hadn't structurally changed between that
version and latest. This is recorded explicitly in each entry's
`verified_via` field rather than silently glossed over, since "verified
against an older version, believed still accurate" is a meaningfully
weaker claim than "verified against latest," and a future reader
shouldn't have to guess which one they're looking at.

Also worth knowing about `rig-core` specifically: as of its latest
release the crate split into a portable `rig-core` (contracts only) and a
separate `rig-agent` (the classic runtime, including `Prompt`/`Agent`),
unified behind a new `rig` facade crate. The `Prompt` trait catalogued
here doesn't even live in `rig-core` anymore in the newest version — worth
knowing if this entry needs revisiting once `rig-core`/`rig-agent`
becomes compilable under whatever toolchain this repo is pinned to by
then.

## What was deliberately *not* done

Per an explicit scoping decision earlier in the session: this pass
**re-verified existing entries only**. Several SDKs (`ollama-rs`, `clust`,
`rig-core`, `anthropic-sdk`, `misanthropic`, `llm-chain`, `genai`,
`reqwest`) have zero `llm-api-prompt` (request-building) entries — only
`llm-api-chat` (request-sending) ones. That might be a real gap (some of
these SDKs likely do have a builder step worth cataloguing, the way
`async-openai` and `gemini-rust` already do) or it might be correct (some
SDKs build requests from plain struct literals with no fluent builder
worth a separate catalogue entry). This wasn't investigated — filling
that gap, if it is one, is future work, not something this pass decided
either way.
