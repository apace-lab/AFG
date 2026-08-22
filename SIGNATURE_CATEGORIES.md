# Signature categories: what changed, and what it taught us

A working note from the session that added a `category` field to the LLM
API catalogue (`datasets/llm_api_functions.json`) and reworked the LLVM-IR
AC scanner's output layout. Kept separate from the operational docs
(`README.md`, `src/AC_FINDER.md`, `src/LLM_API_FINDER.md`, ...) because
those describe how the tools work today; this is the narrower story of one
concept — "category" — and how it evolved across the two catalogues.

**Versions used:** rustc 1.86.0, bundling LLVM 19.1.7 — the last rustc release
before 1.87.0 switched to LLVM 20 (see `rust-toolchain.toml` and
`LLM_API_IR_VERIFICATION.md`).

## What changed

### 1. `find_ac_points_llvm` output reorganized by category

`src/bin/find_ac_points_llvm.rs` used to write one flat JSON file
(`--out ac_matches_llvm.json`). It now takes `--out-dir` (default
`ll_parser/signatures`) and writes one file per AC category actually
matched: `<out-dir>/<category>/<ir-file-stem>.json`. `tests/fixtures.rs`
gained a `run_llvm` helper that merges those files back together so the
existing assertions still work.

### 2. Real LLVM types added to AC LLVM matches

`AcLlvmMatch` gained `return_type`/`parameter_type`, read directly off each
call site's `function_ty` in the parsed IR (`Call::function_ty`, present
from LLVM 15 onward — this repo pins LLVM 19). These are *ground truth from
the compiler*, not the catalogue's hand-written Rust-level type strings —
see "What we learned" below for why that distinction matters.

### 3. All five docs rewritten for length

`README.md` and the four `src/*_FINDER*.md` references were cut from 1,831
lines to 876 — a clean front door in `README.md`, hard-trimmed reference
docs elsewhere (flags/JSON shape kept, essay-length caveats cut to bullets).

### 4. `category` added to the LLM API catalogue

This is the main subject of this note. `datasets/llm_api_functions.json`'s
31 entries were all bare send-calls with no `category` field at all —
unlike `datasets/ac_functions.json`, which has had one since the AC finder
was built. Added:

- `category: "llm-api-chat"` — the outbound call that actually sends the
  assembled request to the LLM service (`Chat::create`, `Ollama::generate`,
  `reqwest::RequestBuilder::send`, ...). All 31 pre-existing entries are
  this kind.
- `category: "llm-api-prompt"` — assembling the request *before* it's sent
  (message/content builders, request builders). 5 new `async-openai`
  entries were added for this: `ChatCompletionRequestUserMessageArgs::content`/
  `::build`, `CreateChatCompletionRequestArgs::model`/`::messages`/`::build`.
  One existing entry, `gemini_rust::Gemini::generate_content`, was
  reclassified into this bucket too — its `taint_role` note already called
  it a "builder-entry" before `category` existed as a field.

Wired through `src/llm_api_finder.rs` (`Signature`/`ApiMatch` structs, the
loader, the matcher) exactly the way `AcSignature`/`AcMatch` already carry
`category` in `src/ac_finder.rs` — same field name, same
`unwrap_or("unspecified")` default for entries that predate the field.

### 5. `sret` / `request_index` / `prompt_arg_index` / `prompt_role` added to every entry

A follow-up refinement, all in `datasets/llm_api_functions.json` — no Rust
code changes, since `parameter_type` was already inert catalogue metadata
that `find_llm_calls` never reads for matching (see "What we learned"
below).

- Every `llm-api-chat` entry whose `return_type` is `Result<T, E>` gets
  `"sret"` prepended to `parameter_type`, modeling the indirect
  struct-return slot RUPTA's PAG treats as a synthetic leading argument.
  This shifts every real argument's position by one.
- Every `llm-api-chat` entry gets `request_index`: the 0-based
  `parameter_type` index of whichever argument carries the assembled
  outbound request — the taint sink RUPTA should treat as "sent to the
  LLM." Not always the last argument: `genai::Client::exec_chat` has a
  trailing `Option<&ChatOptions>` after the real `ChatRequest`, and
  `llm_chain::chains::sequential::Chain::run`'s `request_index` points at
  `Parameters` (the template-fill values), not the trailing `&Executor`
  reference. For builder-consuming calls (`GenerateContentBuilder::execute`,
  `anthropic_sdk::Request::execute`, `reqwest::RequestBuilder::send`),
  `self` *is* the request, so `request_index` points at `self`.
- Every `llm-api-prompt` entry that actually takes prompt/message content
  (not `.build()`, which finalizes already-accumulated builder state and
  takes no new content, and not a plain field setter like `.model()`) gets
  `prompt_arg_index` (same convention as `request_index`) and `prompt_role`
  — `user`/`system`/`assistant` for a builder that constructs exactly one
  role's message, `mixed` for one that takes a whole collection that could
  span roles (`CreateChatCompletionRequestArgs::messages` takes a
  `Vec<ChatCompletionRequestMessage>` — see "What we learned" below for why
  that specific shape matters to this project).

### 6. Real signature drift found and fixed along the way

Verifying the new entries against current `async-openai` (0.41.3) docs
surfaced three catalogue entries that had silently gone stale:

| Was | Now |
|---|---|
| `async_openai::image::Images::create` | `async_openai::image::Images::generate` |
| `async_openai::audio::Audio::speech` | `async_openai::audio::Speech::create` |
| `async_openai::audio::Audio::transcribe` | `async_openai::audio::Transcriptions::create` |

The old entries wouldn't have errored — they'd have just never matched
again on any codebase using a current crate version, silently under-reporting
image/audio calls with no signal that anything was wrong.

## What we learned about categories

**A catalogue's "category" axis is domain-specific, not a fixed shape.**
The AC catalogue's four values (`authentication` | `authorization` |
`policy-enforcement` | `raw-http`) classify *what kind of security decision*
a call makes. The LLM catalogue's two new values (`llm-api-prompt` |
`llm-api-chat`) classify *where in the request lifecycle* a call sits —
before send vs. the send itself. Same field name, same code shape
(`Signature`/`Match` struct field, `unspecified` fallback, copied onto every
match in the JSON output), but the two catalogues categorize along
completely different axes because they're answering different questions.
Don't assume a category scheme transfers between catalogues just because
the field does.

**Builder-pattern APIs create a real "prepare vs. send" split worth
cataloguing separately.** Every SDK in this catalogue that uses
`derive_builder`-style construction (`XArgs::default().field(...).build()?`)
has the same shape: setter methods return `&mut Self`/`Self` and are
individually uninteresting (any struct's builder has a `.content()` or
`.model()`), but `.build()` is the one call that actually produces the
request value, and the *following* call (`Chat::create`, `Ollama::generate`)
is the one that leaves the process. A scanner that only catalogues the send
call misses "this program is constructing a prompt but I can't yet tell if
it's sent" as a distinct, useful signal — e.g., for spotting a prompt built
from tainted user input, you want to know about the builder chain, not just
the eventual `.send()`.

**Generic method names are safe to catalogue *only* under MIR/LLVM-IR
matching, not source-text matching.** `.build()`, `.content()`, `.messages()`
are far too generic to catalogue for `find_ac_points_src`/`find_ac_points_js`
(any builder pattern in the codebase would false-positive) — but they were
added here for `find_llm_calls`, which matches against **fully-qualified**
MIR callee text (`async_openai::types::chat::ChatCompletionRequestUserMessageArgs::build`,
not bare `.build(`). The catalogue entry's `fn_name` being fully qualified
is what makes a generic-sounding method name safe to match here; the same
string would be unusably noisy in a source-text scanner. This is the same
reasoning `find_ac_points`/`find_ac_points_llvm` already lean on for
`short-name` gating (see `src/AC_FINDER.md`) — just now confirmed by
actually adding a generic-name entry, not just designing around one.

**A "prepare" call's argument shape can itself be the leak signal —
that's the whole point of `prompt_role: "mixed"`.** AFG's core purpose
(`README.md`) is finding cross-user overlap: two users' tainted data
reaching the same object. `CreateChatCompletionRequestArgs::messages`
takes a single `Vec<ChatCompletionRequestMessage>` — nothing stops a
caller from pushing more than one user's turn into that one `Vec` before
sending it (a naive multi-turn chat cache, a batched moderation pass, ...).
Marking that argument `mixed` rather than `user`/`system`/`assistant`
records, right in the catalogue, that this specific call shape is a
plausible cross-user mixing point worth the taint analysis's attention —
not just "a prompt is being built here." A single-role builder like
`ChatCompletionRequestUserMessageArgs::content` can't structurally do
that (it takes one string), so it gets a specific role instead.

**Not every detail belongs in this repo's catalogue *and* code — some of
it is metadata for a consumer we can't see.** `sret`/`request_index`/
`prompt_arg_index`/`prompt_role` were added purely to the JSON, with zero
changes to `src/llm_api_finder.rs`, because `return_type`/`parameter_type`
were already established as pass-through metadata for RUPTA's own
`PointerAnalysis::isTaintedFunction` (`_schema_notes.usage` in the JSON
itself says as much) rather than anything `find_llm_calls`'s own MIR-regex
matching reads. Whether a given `Result<T, E>` actually gets ABI-lowered
via a hidden return-slot argument is a fact about RUPTA's own PAG
construction — code that lives outside this repository — not something
derivable from the crate's public Rust signature alone. Where a catalogue
field's *meaning* depends on an external, unauditable consumer, the
responsible move was asking rather than inferring an ABI rule from first
principles and risking silently-wrong indices across 36 entries.

**A dataset's `verified_via` provenance is what makes drift detectable
instead of silent.** The three stale `async-openai` entries above didn't
throw errors — a signature that no longer matches anything just quietly
stops contributing matches, with no signal in the tool's output that it's
now dead weight. The only reason it got caught here at all was manually
re-checking `verified_via: "context7:/64bit/async-openai"` entries against
live docs before adding new ones next to them. Neither catalogue has any
automated staleness check today (e.g. CI diffing catalogued signatures
against a fresh docs.rs/crates.io fetch) — this was a spot-check of one
library's entries against current docs, not a guarantee the other 8
libraries' entries are current.

**"Category" defaults have to be backward-compatible, not just present.**
Both catalogues fall back to a literal `"unspecified"` string (in Rust, via
`.unwrap_or("unspecified")`) rather than `Option<String>`/`null` for entries
missing the field. That keeps every consumer of `Signature`/`AcSignature`
non-`Option`al — no new `if let Some(category) = ...` branches needed
anywhere `category` is read or printed — at the cost of `"unspecified"`
being a real string value that has to be documented and treated as
"probably `llm-api-chat`" rather than "no opinion." Every entry in the LLM
catalogue was actually given an explicit `category` in this pass, so
nothing live depends on that fallback today — but it's what makes adding a
37th entry without a `category` a non-breaking mistake instead of a load
error.
