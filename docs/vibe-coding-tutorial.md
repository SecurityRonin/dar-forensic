# Vibe Coding, For Real: Building `dar-forensic` From Scratch

A step-by-step, follow-along tutorial for an intern learning to build *production-grade*
software by directing an AI coding agent (Claude Code). We use the real story of how
`dar-forensic` — a forensic-grade, pure-Rust reader for DAR archives — went from an empty
folder to a published crate, across versions 0.1.0 → 0.6.0.

**Author:** [Albert Hui](https://www.linkedin.com/in/alberthui) | **Version:** 1.1 | **Updated:** 2026-06-08

> **Follow along with the source.** The finished crate — every commit, fixture, and the
> `lzo` sibling crate — lives at **<https://github.com/SecurityRonin/dar-forensic>**. Clone
> it and read the git history alongside this tutorial; the RED/GREEN commits *are* the loop.

> **What "vibe coding" means here.** Not "type a vibe and ship whatever falls out."
> It means *you* are the architect, reviewer, and QA, and the AI is a fast, tireless
> implementer. Your leverage is **clear intent + non-negotiable disciplines + independent
> verification**. The vibe is the conversation; the rigor is yours.

---

## Executive Summary (read this first)

- **You will build:** a Rust library crate that parses a real, undocumented-ish binary
  file format, decodes six compression codecs, verifies integrity, and flags forensic
  anomalies — hardened against malicious input and validated against real-world files.
- **The one loop you must internalize:** `Intent → RED (failing test on real data) →
  GREEN (minimal code) → Verify independently → Commit`. Everything below is variations
  on this loop.
- **The single highest-leverage move:** write your "house rules" *once* so the agent
  enforces them on every turn (see **Chapter 1 — House Rules** below). Skipping this is
  the #1 reason AI-assisted projects rot.
- **Time:** ~5–8 focused sessions. Each chapter below is roughly one session.
- **Prerequisites:** comfort reading code, basic git, a terminal. You do **not** need to
  be a Rust expert — you need to be a good director and a skeptical reviewer.

If you do only one thing: **never trust code you validated only with tests you wrote
yourself.** The whole tutorial is built around defeating that trap.

---

## How to use this tutorial

Each chapter has the same shape:

1. **Goal** — what we're adding this session.
2. **The prompt(s)** — copy-pasteable instructions to give the agent. Adapt the wording;
   the *structure* is the lesson.
3. **What good looks like** — how to tell the agent did the right thing.
4. **Your job** — what *you* must check that the agent can't check for itself.

Copy the prompts, but read the "Your job" boxes twice. That's where the engineering is.

---

## Chapter 0 — Setup (15 minutes)

Install the tools and prove they work before you write a line of intent.

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version          # expect 1.85+

# The agent (Claude Code)
npm install -g @anthropic-ai/claude-code   # or your org's install path
claude --version

# Git, configured
git --version
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

Then create the project and open the agent *inside it*:

```bash
mkdir dar-forensic && cd dar-forensic
git init
claude          # start the agent in this directory
```

> **Your job:** the agent works best with a tight, real working directory and a clean git
> history. Commit early and often — every RED and every GREEN is a commit. Git is your
> undo button and your audit trail of what the AI actually did.

---

## Chapter 1 — House Rules (the most important chapter)

Before any feature, teach the agent how *you* work. These rules live in a `CLAUDE.md` file
that the agent reads on every session, so it self-enforces them without you repeating
yourself. This is the difference between an intern who needs supervision and one who
internalized the team's standards.

Create `CLAUDE.md` with the disciplines that actually made `dar-forensic` good:

```markdown
# Engineering disciplines for this project

## Test-Driven Development — mandatory
- RED then GREEN, in SEPARATE commits.
  1. Write a failing test that defines the behavior. Run it. Confirm it FAILS.
  2. Write the minimal code to pass. Run it. Confirm it PASSES.
  3. Refactor with tests green.
- The RED commit is the proof TDD actually happened. No combined commits.

## Doer-Checker — never trust your own tests alone
- Code + tests written by the same author share blind spots.
- Validate against REAL external data (files from real tools), not only fixtures
  you constructed yourself.

## Secure by default
- The zero-config path must be the safe one.
- Fail loud: no swallowed errors, no fallback that hides a bug as a default value.
- Make wrong usage structurally hard, not just "documented as inadvisable."

## Scope fidelity (YAGNI)
- Build exactly what the current task needs. No speculative options.
- Search before you write a helper — reuse beats re-create.
- Minimal diffs: change only the lines the task requires.

## Fit the codebase
- Match local naming, error handling, and test structure.
- Comments explain WHY, not WHAT.
```

> **The lesson:** you encoded your standards *once*. From now on, when you say "add
> feature X," the agent already knows to write the failing test first, validate against a
> real file, and keep the diff minimal. You stopped managing and started *directing*.

> **Your job:** read the agent's plan before it codes. If it proposes a speculative
> "while I'm here" addition, cut it. Scope discipline is enforced by you, every time.

---

## Chapter 2 — Genesis: pick a real problem and research the spec (v0.1.0)

**Goal:** a crate that opens a real DAR archive and lists its entries.

We didn't start by coding. We started by **researching the format** and **getting a real
artifact**, because you cannot test-drive a parser against a format you're guessing at.

**Prompt:**

```
We're building `dar-forensic`: a pure-Rust, decompress-only reader for Denis Corbin's
DAR (Disk ARchiver) format, aimed at digital forensics.

First, research the DAR on-disk format (libdar's archive layout, the catalogue, the
header_version, the seqt_catalogue escape sequence). Summarize the layout you'll rely on,
and cite where each fact comes from. Then scaffold a Cargo library crate.

Do NOT write the parser yet. I want to see the format notes and the crate skeleton first.
```

**What good looks like:** the agent produces `docs/implementation-notes.md` with the real
layout (this file exists in the repo — it's where format facts live), and a minimal
`cargo new --lib` skeleton. Facts are attributed, not asserted from thin air.

Now get a real archive to test against — this is the Doer-Checker rule in action:

```bash
brew install dar           # or your platform's package
mkdir -p /tmp/corpus/files
printf 'hello corpus\n' > /tmp/corpus/files/hello.txt
dar -c /tmp/archive -R /tmp/corpus -g files/hello.txt
cp /tmp/archive.1.dar tests/data/v11_hello.dar
```

**Prompt (the first TDD loop):**

```
Here is a REAL dar 2.8 archive at tests/data/v11_hello.dar containing one file
"files/hello.txt" with 13 bytes.

RED: write an integration test that opens it and asserts it lists exactly one file entry
named "files/hello.txt" of size 13. Run it, show me it fails. Commit as the RED commit.

Then GREEN: implement the minimal parser to make it pass. Run it, show me it passes.
Commit separately as the GREEN commit.
```

> **Your job — the Doer-Checker check:** confirm the `.dar` was produced by the *real*
> `dar` tool, not hand-crafted by the agent. A test where the agent made both the input
> and the parser proves nothing. Real tool in, your parser out, byte-exact match.

`★ Why this matters` — the very first feature establishes the pattern that carried the
whole project: every parser claim is checked against output from the authoritative
producer. By v0.5.0 the repo had real fixtures for formats 7–11 and a reverse-engineered
edition-1 archive — each one a real `.dar`, never a fake.

---

## Chapter 3 — Decode *every* variant (completeness is non-negotiable) (v0.1.0 → v0.2.0)

**Goal:** transparently decode every codec a DAR archive can use (gzip, bzip2, xz — and
later zstd, lz4, lzo) — because a forensic tool that can't read a variant is worse than
useless: it forces the examiner to reach for another tool, or risks handing back wrong
bytes.

This chapter teaches **forensic completeness + fail-loud + a fully-auditable, pure-Rust
read path.**

> **The principle.** We are a *forensic* tool. An examiner must be able to read **every**
> archive they encounter — there is no acceptable build that silently can't read, say, an
> lzo entry. So decoding every codec is a first-class, always-present capability, **not an
> opt-in**. The only hard dependency rule is *pure-Rust decoders only*, so the entire read
> path stays auditable and free of C/`unsafe` surprises.

**Prompt:**

```
DAR entries can be compressed (gzip 'z', bzip2 'y', xz 'x'). Add transparent
decompression for ALL of them — decoding is mandatory, not optional.

Constraints:
- Pure-Rust decoders only (no C deps): flate2 with rust_backend, bzip2-rs, lzma-rs.
- The reader must ALWAYS be able to decode every codec dar can write. Completeness is
  the whole point of a forensic tool.
- Fail loud, never wrong: on malformed input return a clear, typed error — NEVER return
  compressed bytes as if they were plaintext.

TDD as usual: RED test per codec against a real `dar -z<codec>` fixture, then GREEN.
```

**What good looks like:** every codec decodes through one dispatch path, driven by real
fixtures (`v11_gzip.dar`, `v11_bzip2.dar`, `v11_xz.dar`). `cargo test` exercises all of
them by default; there is no configuration in which a normal build can't read a codec dar
supports.

> **Your job — the completeness check:** enumerate *every* codec the format allows and
> confirm the reader handles each, against a real archive produced with that codec. The
> gap you don't test for is the archive your examiner can't open in court.

`★ The design idea` — secure-by-design here is "never hand back mis-decoded bytes."
Whichever codec is involved, the caller gets either correct plaintext or a loud typed
error — never compressed bytes masquerading as the file. For a forensic tool, *silent
wrong output is the worst possible failure*, so the architecture makes it impossible.

> **A real design-evolution moment (and why this chapter was rewritten).** Our first cut
> made each codec an *optional* Cargo feature with a "lean," zero-dependency build —
> optimizing supply-chain size for one niche (a stored-only corpus). On review we judged
> that the wrong default for a forensic tool: optionality makes it *possible* to ship a
> reader that can't read an archive. Completeness wins, so codecs become mandatory.
> **Lesson for the intern:** even a deliberate, well-reasoned design can be wrong for your
> domain. Revisiting and reversing it — loudly, in the changelog — is a feature of good
> engineering, not an admission of failure. Ask of every "optional," *"optional for whom,
> and what breaks for the person who needed it?"*

---

## Chapter 4 — The reader/analyzer split, and forensic value (v0.2.0 → v0.4.0)

**Goal:** turn a "file reader" into a "forensic tool" — integrity verification and anomaly
detection — while keeping the raw reader clean.

We grew the public API deliberately, one capability per TDD cycle:

| Capability | What it does | Prompt seed |
|---|---|---|
| `extract_to<W: Write>` | stream an entry to any writer (multi-GiB safe) | "stream without buffering the whole file" |
| `verify(path)` | recompute libdar's per-file CRC vs the stored one | "return Match / Mismatch{stored,computed} / NotStored; never withhold bytes" |
| `audit()` | walk the catalogue, return severity-graded findings | "absolute paths, `..` traversal, dup paths, future timestamps, control bytes, unsupported codecs" |
| `bodyfile()` | render a Sleuth Kit `mactime` timeline line | "TSK type/perms mode form; escape `\|`, `\\`, control bytes" |
| `entry_count` / `iter_entries` | O(1) count + lazy iteration | "don't clone the whole Vec for a streaming consumer" |

**A representative prompt:**

```
Add DarReader::audit() -> a list of forensic findings, most-severe first.

Each finding must distinguish layers of certainty: state OBSERVED facts, frame inferences
as "consistent with ...", and NEVER assert legal conclusions. Each carries a stable code,
a Severity, and a human-readable note.

Findings live in their own module (src/findings.rs), separate from the raw reader in
lib.rs. RED tests first, on crafted-but-valid catalogues.
```

> **Your job — the overstatement check:** read the finding *messages*. A forensic tool
> that says "this proves tampering" is wrong; "consistent with tampering, the examiner may
> draw conclusions" is right. The agent will happily overstate if you let it. You are the
> editor of epistemic honesty.

`★ Architecture lesson` — notice we kept raw decoding (`lib.rs`) separate from forensic
interpretation (`findings.rs`). Later, the findings were normalized onto a shared report
model (`forensicnomicon::report::Finding`) so this crate speaks the same vocabulary as its
sibling forensic crates. Clean module boundaries made that refactor a 2-commit change, not
a rewrite.

---

## Chapter 5 — When the spec fights back (v0.3.0)

**Goal:** support ancient and awkward archives — DAR edition 1 (from 2002) and pre-format-8
archives that locate their catalogue differently.

Real formats are messy. This is where "research the spec, then assume real data violates
it" earns its keep.

**Prompt:**

```
Some archives don't match the modern layout:
- Format edition 1 (dar 1.0.x): no EA flag byte, no ctime, no FSA; cat_file is
  size·offset only (no storage_size/CRC); root is named "root".
- Pre-format-8: no per-entry compression byte; the catalogue is located via the trailing
  "terminateur", and the whole archive shares one global codec.

I have a REAL edition-1 archive and real pre-8 fixtures. Reverse-engineer the layout from
the bytes, validate byte-for-byte against the real archive, and make cat_file parsing
format-aware across editions 1 / 2–7 / 8+. RED with the real fixtures first.
```

> **Your job:** when the agent says "the layout is X," ask "validated against which real
> archive?" Edition-1 support was *reverse-engineered from a real dar-1.0.0 archive* and
> checked byte-for-byte. If the agent can't point at a real artifact, the claim is a guess.

`★ Robustness lesson` — we also made the parser *degrade gracefully*: named-pipe and
socket inodes are skipped (not fatal), an unmodelled entry type marks the listing
"incomplete" loudly rather than returning a silently-short list. Robust code never turns a
surprise into wrong output.

---

## Interlude — Ground truth: real-world corpora and ancient toolchains

The single fixture from Chapter 2 proves the parser works on *one* archive. A forensic
tool has to work on the messy long tail. Two techniques carried this project, and both are
core "vibe coding" skills because you direct the *agent* to do the grunt work of building
the evidence base.

### A. Test against a real-world *corpus*, not one file

One `hello.dar` is a smoke test. Confidence comes from running the reader over **many real
archives of every shape it will meet in the field** — every format version, every codec,
every block-size option, and real *content* of every entropy profile (text, binaries,
already-compressed blobs, images, empty/1-byte edges).

We did this at three levels — and the first is the one that *defines done*:

- **The contemporary tool's real output — the MVP must-have.** This crate exists to read
  what real forensic tools produce *today*, so the non-negotiable baseline was reading
  **two real DAR archives produced by Passware Kit Mobile 2026 v3.0** (the contemporary
  mobile-forensics suite, which emits DAR v9) — **correctly and in full.** We generated
  them on a small *controlled* sample built for cross-platform representativeness: two test
  handsets, **one iPhone and one Android**, imaged with the tool. That is what "it works"
  actually means for a forensic tool: not "passes a synthetic test," but "reads the
  evidence your examiner will hand you, every byte of it." It earned its keep immediately —
  Passware's real output encodes large (>32-bit) timestamp epochs with the infinint `0x40`
  terminal, which a parser that only handled the `0x80` form rejects outright. No hand-built
  fixture would have caught that; a real archive did, on day one. **If your tool can't read
  the real tool's real files, completely, nothing else you tested matters yet.**
  *(Use a controlled sample of devices/data you own — never someone else's evidence — so
  the corpus is reproducible and yours to share.)*
- **dar archives across versions/codecs/options** — real fixtures for formats 7–11, each
  codec (`v11_gzip/bzip2/xz/zstd/lz4/lzo`), and per-block variants (`pb_gzip`, `pb_lz4`,
  `pb_zstd`) produced with options like `dar -zlz4:9:1024` (1 KiB blocks → a 136 KB
  payload spanning ~133 blocks). Each is a *real* `.dar`, byte-exact-verified.
- **A 32 MB real-file corpus for the `lzo` decoder** — a dictionary, real Mach-O binaries,
  a photo, an already-gzipped blob, real source/prose — compressed at every level, every
  block decoded byte-exact.

**The clearest proof came late — and it stung.** When we added multi-volume (sliced)
archive support, the synthetic `dar -s` fixture passed: green, byte-exact, 100% covered. We
shipped it. Then we re-sliced a **real 52 GB Android extraction** (`dar_xform`, 13 volumes)
and pointed the reader at it. It *failed* — and in failing exposed two real format details
the synthetic fixture's assumptions had hidden: the catalogue is keyed by the archive's
`data_name`, not the slice's regenerated `internal_name`; and real format-11.1 archives
carry an in-place path the synthetic one had omitted. Two bugs, found in minutes, by one
real artifact — *after* a fully-passing synthetic suite. **A green synthetic test is
necessary, never sufficient. The real artifact is the judge.** (This is also why you keep a
few *large, real* samples around: the bug lived at a slice boundary 40 GB in.)

**Prompt:**

```
Don't stop at one fixture. Build a real-world corpus and run the reader over ALL of it:
- one archive per format version we support, from the matching dar release;
- one per codec, and per-block variants (e.g. `-zlz4:9:1024` to force many blocks);
- real file content of varied entropy (text, a binary, an already-compressed blob,
  empty and 1-byte edges).
Decode every entry and assert byte-exact against the originals. Report any mismatch with
the exact file and offset.
```

> **Your job — the Doer-Checker rule, at scale:** synthetic fixtures you hand-build share
> your blind spots and miss real-world quirks (generator-specific deviations, odd block
> boundaries, encoding edge cases). A real, diverse corpus is what turns "passes my tests"
> into "works on real evidence." When the agent says "it works," ask *"on how many real
> archives, of how many shapes?"*

`★ Why scale matters` — the multi-block lz4 bug class only appears when a payload spans
*many* blocks; the `lzo` differential run only became meaningful once millions of
*near-valid mutated* inputs were thrown at it. Volume and diversity find what a curated
handful never will.

### B. Spin up old compilers in Docker to manufacture ground truth

Here's the catch with old formats: to produce a **format-7** archive you need **dar
2.3.12**, whose pre-2.4 C++ **won't compile on a modern toolchain at all.** You can't
download a 2008 binary you trust, and you can't build it natively. The answer is to
reconstruct the producer's era in a container.

That's exactly how `tests/data/v7_hello.dar` was made — quoting the test file itself:

> *Created with dar 2.3.12 (built from the SourceForge release tarball in a `gcc:4.9`
> container — pre-2.4 C++ won't compile on a modern toolchain).*

**Prompt:**

```
I need a real DAR format-7 archive as ground truth, but format 7 is produced by dar 2.3.x,
which won't build on a modern compiler. Use Docker with an old toolchain (e.g. gcc:4.9) to
build dar 2.3.12 from its SourceForge source tarball, create a tiny archive inside the
container, and copy it out to tests/data/. Record the exact build + create commands in a
comment so it's reproducible.
```

The shape of what the agent runs:

```bash
# Build an ancient dar inside a matching-era toolchain, make an archive, copy it out.
docker run --rm -v "$PWD":/out gcc:4.9 bash -c '
  cd /tmp && curl -sSL <sourceforge>/dar-2.3.12.tar.gz | tar xz && cd dar-2.3.12 &&
  ./configure --disable-nodump-flag && make -j &&
  mkdir -p /src/files && printf "hello format 7\n" > /src/files/hello.txt &&
  ./src/dar -Q -c /work/v7 -R /src -g files/hello.txt &&
  cp /work/v7.1.dar /out/tests/data/v7_hello.dar'
```

> **Your job — provenance:** record the *exact* tool version, source URL, container image,
> and commands in the test file (we do, for every old fixture). A forensic fixture whose
> origin you can't reproduce is not evidence — it's a magic blob. Reproducibility is the
> whole game.

`★ The meta-skill` — "vibe coding" isn't only writing the crate; it's directing the agent
to **manufacture the evidence the crate is tested against** — including resurrecting a
decade-old compiler in a sandbox. The agent is tireless at exactly this kind of fiddly
archaeology; your job is to insist the result is real and reproducible.

---

## Treat every byte as hostile — hardening against malicious input

A forensic tool has a threat model most software ignores: **the input is evidence, and
evidence can be adversarial.** A suspect — or malware on the imaged device — may hand you an
archive crafted to crash your parser, hang it, exhaust memory, or, worst of all, make it
silently emit wrong bytes that mislead an investigation. So the rule is absolute: **every
byte that comes from the file is hostile until the parser has bounds-checked it.** A tool
that segfaults on a crafted archive isn't just buggy — its output is hard to defend.

Here's how we hardened the DAR parser (and the `lzo` decoder), each technique tied to the
attack it stops:

| What a malicious file can attempt | The hardening |
|---|---|
| Memory corruption via a malformed field | `#![forbid(unsafe_code)]` (lzo) / `unsafe_code = "deny"` (dar): every index/slice is bounds-checked by the compiler — out-of-bounds is a typed error, never undefined behaviour. |
| Integer overflow / DoS from a huge length | **Bound every length read from the file.** DAR "infinint" values are capped at 64 bits, killing both the leading-zero-run DoS and the `skip × 8` multiply-overflow; CRC/field widths are bounded so a crafted length can't trigger a giant allocation. |
| Decompression bomb (1 KB → 10 GB) | A streaming output **cap** (`CapWriter`): decompression aborts loudly the moment output would exceed the bound, instead of filling RAM. |
| Wedged / infinite-loop parser | The catalogue walk and block loop are bounded by the (already bounded) input length — no input makes them run forever. |
| Silent wrong output | **Fail loud, never wrong:** any malformed structure returns a typed `Corrupt` error with context. The parser never guesses, never silently falls back to "treat it as stored," never returns partial bytes as if whole. |

And then we tried to break it on purpose:

- **Fuzz the whole reader** — a `cargo-fuzz` (libFuzzer) target feeds arbitrary bytes into
  parsing and asserts the invariant *"never panics — only `Ok` or a typed error."* CI
  builds the fuzz target on every push so it can't rot; you run extended campaigns locally
  with `cargo fuzz run`.
- **The `lzo` decoder, fuzzed *and* differential-tested** — millions of arbitrary and
  mutation-fuzzed inputs (never a panic), cross-checked byte-for-byte against an independent
  decoder, so even *valid-looking* malformed input can't produce divergent output.

**Prompt:**

```
Treat this parser as ingesting adversarial input. Harden it:
- forbid/deny unsafe so there is no memory-corruption class;
- bound EVERY length/size/count read from the file (cap infinints, bound allocations) so a
  crafted value can't overflow or trigger a giant allocation;
- add a decompression-bomb cap on decompressed output;
- on any malformed input, return a typed error with context — never panic, never return
  wrong or partial bytes.
Then add a cargo-fuzz target over the whole reader asserting "never panics," and build it
in CI. Show me crafted-input tests for the bounds (truncated length, oversized length,
decompression bomb).
```

> **Your job — the adversarial mindset:** for every field the parser reads, ask *"what is
> the worst value a malicious file could put here, and what does my code do with it?"* The
> agent writes the happy path by default; *you* supply the paranoia. One crafted-input test
> per guard is worth more than a hundred well-formed fixtures.

`★ Why "fail loud, never wrong" is the keystone` — for ordinary software a silent wrong
result is a bug; for a forensic tool it can corrupt a conclusion that ends up in court. The
architecture is built so the *only* outcomes are correct output or a loud, typed error.
That single invariant is what makes every other hardening step worth doing.

---

## Chapter 6 — Hitting a wall: build the dependency you wish existed (the `lzo` story)

**Goal:** decode LZO-compressed entries — for which **no safe pure-Rust decoder existed.**

This is the most important *judgment* chapter. The honest options were:

1. Add a C dependency (`liblzo2`) — breaks the pure-Rust, easy-to-audit promise.
2. Use an existing Rust port — but the mature ones are GPL-2.0 (can't link into MIT).
3. **Build a small, safe, dependency-free LZO decoder ourselves**, as a separate crate.

We chose (3). The lesson: sometimes the right move in a build is to *step out and build a
clean dependency*, then come back. We created `~/src/lzo` — a `no_std`,
`#![forbid(unsafe_code)]`, zero-dependency LZO1X decompressor — as its own project, with
its own tests, CI, and release.

**Prompt (sibling crate):**

```
Build a new crate `lzo`: a safe, no_std, zero-dependency, #![forbid(unsafe_code)]
LZO1X *decompressor* (decode only).

Read the LZO1X algorithm from the authoritative reference (the Linux kernel's
lzo1x_decompress_safe.c). Then TDD it against vectors produced by the reference C
liblzo2 — liblzo2 encodes, our Rust decodes, the round-trip must be byte-exact. The two
share no code, so a mismatch can only mean our decoder is wrong.

Harden against malicious input: a libFuzzer target, a "never panics on arbitrary bytes"
test, and typed errors for every failure mode.
```

Then we **validated it three ways** before trusting it (Doer-Checker, maximally):

- Round-trip vs the reference C `liblzo2` across a 32 MB corpus of *real* files (a
  dictionary, real binaries, a photo, an already-compressed blob) at every compression
  level — byte-exact.
- **Differential testing** against an *independent* decoder (`rust-lzo`, derived from
  Linux): identical output on real data, and across 3,000,000 mutation-fuzz inputs, zero
  divergence and zero panics.
- 100% line coverage, all reached through the public API.

Only then did we publish it (crates.io `lzo`), and wire it into `dar-forensic` behind an
`lzo` feature.

> **Your job — the dependency decision:** when the agent says "there's no good library for
> this," interrogate it. Is that *true* (we checked crates.io, the licenses, the maturity)?
> Is building one *worth it* (LZO is small and well-specified; a JPEG decoder would not
> be)? "Build vs. depend" is an engineering judgment the AI can inform but you must own.

`★ Validation lesson` — note the escalation: synthetic vectors → real-file corpus →
*differential against a second implementation* → fuzzing. Each layer catches what the
previous can't. Differential testing is the gold standard: two independent implementations
agreeing on 3M inputs is far stronger evidence than any number of tests you wrote yourself.

---

## Chapter 7 — Integrate, and let the project move under you (v0.4.0 → v0.5.0)

**Goal:** wire the published `lzo` crate into `dar-forensic`, on top of a `main` that had
moved (a parallel refactor normalized findings onto a shared report model).

This chapter teaches **working on a living codebase** and **clean integration.**

**Prompt:**

```
The `lzo` crate is published. Wire dar-forensic's lzo arm to it (feature-gated, default
on), mirroring how lz4 raw blocks are decoded. unsafe_code stays "deny".

TDD against a real `dar -zlzo` fixture (catalogue is itself lzo-compressed, so listing
exercises it too). Make `unsupported_codec` feature-gate the raw-block codecs (lz4, lzo)
consistently. Land it CI-green.
```

What actually happened — and what to learn from it:

- The agent discovered `main` had advanced with a breaking refactor. It **rebased onto the
  new main** (a clean 2-commit fast-forward) rather than fighting the old base.
- Making lzo decodable surfaced a subtle truth: the "unsupported codec" finding is now only
  reachable in a *lean* build. The fix wasn't to weaken the test — it was to make the
  coverage gate measure the **union of feature configurations**. Correctness over
  convenience.

> **Your job:** when CI goes red after an integration, read *why* before "fixing" it. A
> coverage gate failing because a line became unreachable in the default build is telling
> you something true about your design. The right response is often to change the *gate's
> model*, not to delete the test.

---

## Chapter 8 — The safety net: CI, fuzzing, and supply-chain hygiene

**Goal:** make quality automatic, so neither you nor the agent can regress it by accident.

This is what makes the difference between a toy and a shippable crate. We set up:

```
fmt        — cargo fmt --check
clippy     — pedantic lints, -D warnings, across feature configs
test       — default + --all-features + --no-default-features
deny       — cargo-deny: advisory, license allowlist, dependency bans
msrv       — builds on the declared minimum Rust version
fuzz       — cargo-fuzz target builds on nightly
secrets    — gitleaks scan
coverage   — 100% line coverage (union of feature configs) + a public-API (e2e) gate
geiger     — unsafe-code audit (informational)
```

Plus: every GitHub Action **pinned to a commit SHA** (not a moving tag), `renovate.json`
to auto-update those pins, and a `.pre-commit-config.yaml` so the same checks run before
each commit locally.

**Prompt:**

```
Set up CI to the following standard: SHA-pinned actions, fmt/clippy/test across feature
configs, cargo-deny, MSRV, a fuzz build check, gitleaks, and a 100%-line coverage gate.
Add renovate and a pre-commit config mirroring the local hooks.
```

> **Your job:** the coverage gate is your insurance that "we'll add a test later" never
> happens. 100% line coverage forces every branch to be exercised. The fuzz target is your
> insurance against the inputs you didn't imagine. Insist on both before calling anything
> "done."

`★ Supply-chain lesson` — pinning actions to SHAs and gating on `cargo-deny` means a
compromised upstream tag or a newly-disclosed advisory can't silently enter your build.
For a *forensic* tool, where the output may end up in court, provenance is a feature.

---

## Chapter 9 — Shipping: semver, changelog, release

**Goal:** publish a version users can depend on.

```bash
# 1. Decide the bump (semver): new feature → minor (pre-1.0: 0.x.0); docs/fix → patch.
# 2. Update Cargo.toml version + cut a CHANGELOG section (Keep a Changelog format).
# 3. Dry-run, then publish.
cargo publish --dry-run
cargo publish

# 4. Tag and create a GitHub release.
git tag -a v0.5.0 -m "dar-forensic 0.5.0 — lzo decompression"
git push origin v0.5.0
gh release create v0.5.0 --title "dar-forensic 0.5.0" --notes-file -
```

> **Your job:** `cargo publish` is **irreversible** (a version can be yanked but never
> deleted). Always dry-run first, always confirm the right version, and never let the agent
> publish without an explicit go. Treat any outward-facing, hard-to-reverse action as a
> decision *you* make.

---

## The core loop, in one picture

![The core loop: State intent → RED (failing test on real data) → agent confirms it FAILS → GREEN (minimal code) → agent confirms it PASSES → Verify independently → Commit (RED then GREEN) → CI green → back to intent. If verification finds something off, return to RED.](images/core-loop.png)

It cycles — the last step returns to the first:

1. **State intent** — one feature, clearly scoped.
2. **RED** — write a failing test against *real* data.
3. Agent runs it → **confirm it FAILS.**
4. **GREEN** — minimal implementation.
5. Agent runs it → **confirm it PASSES.**
6. **Verify independently** — real artifact? honest claims? minimal diff? *(If anything's off, go back to step 2.)*
7. **Commit** — two commits (RED, then GREEN) → **CI green** (fmt · clippy · test · coverage · fuzz · deny) → back to step 1.

The loop is small on purpose. Small loops keep the agent honest and keep you in control.

---

## Prompt phrasebook (steal these)

Patterns that actually drove this build:

- **Scope a feature:** *"Add X. TDD: RED test first against a real fixture, show me it
  fails, commit; then GREEN minimal impl, show me it passes, commit separately."*
- **Force real-data validation:** *"Validate against a file produced by the real `<tool>`,
  not a fixture you constructed. Show me the tool command you used."*
- **Demand a plan before code:** *"Don't write code yet. Show me the plan, the files
  you'll touch, and the trade-offs."*
- **Keep it honest:** *"State observed facts vs. inferences. Don't overstate. If you're
  relying on something you read earlier, say 'based on my earlier reading,' not as
  present-tense fact."*
- **Interrogate a dependency:** *"Is there really no existing crate for this? Check
  crates.io, licenses, and maturity before we build our own."*
- **Build from the spec — but trust the artifact over it:** *"Find the authoritative spec
  first (the RFC / standard / reference source — e.g. the kernel's
  `lzo1x_decompress_safe.c`) and implement to it, citing where each rule comes from. Then
  assume the spec is wrong in subtle ways — most are. When a real-world artifact, or the
  production implementation's actual behavior, disagrees with the written spec, the artifact
  wins. Real files and shipped code are the ground truth; the spec is only a hypothesis
  about them."*
- **Differential-test against an existing implementation:** *"Compare our output
  byte-for-byte against an independent implementation, on real data AND on millions of
  fuzzed/mutated inputs. Agreement at that scale is how we surface the subtle errors our
  own tests can't — because they share our blind spots."*
- **Verify, don't assume:** *"Run it and show me the output. Don't tell me it works —
  show me."*

---

## Anti-patterns (how AI-assisted projects rot)

- **Letting the AI write the test *and* the code *and* declaring victory.** That's a closed
  loop with shared blind spots. Always inject real external data or a second implementation.
- **Accepting "done" without seeing output.** "I added the feature" is a claim. The passing
  test run is evidence. Demand evidence.
- **Scope creep by helpfulness.** The AI loves to add "while I'm here" options. Every
  unrequested addition is surface area to maintain and get wrong. Cut it.
- **Overstatement in prose.** Findings, READMEs, and docs drift toward marketing. For a
  forensic tool, that's a correctness bug. Edit for epistemic honesty.
- **Trusting a green checkmark you don't understand.** When CI passes or fails, read *why*.
  The gate is a model of your quality bar; keep the model honest.
- **Big-bang commits.** One giant "implement everything" commit destroys reviewability and
  the TDD audit trail. RED then GREEN, small and separate.

---

## Exercises for the intern

Do these against this repo to feel the loop in your hands:

1. **Reproduce one TDD cycle.** Pick an existing test in `tests/synthetic.rs`, delete the
   code that makes it pass, watch it go red, and re-implement it green. Notice how the test
   *specifies* the behavior.
2. **Break the Doer-Checker rule on purpose.** Write a parser test where you also generate
   the input by hand. Then test the same code against a real `.dar` from the `dar` tool.
   Find a case where the hand-made fixture passed but the real file revealed a bug.
3. **Add a finding.** Pick a new anomaly (e.g., "entry size wildly larger than the
   archive"), TDD it in `src/findings.rs`, and make sure `audit()` reports it — phrased as
   "consistent with," never as proof.
4. **Run the safety net.** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
   `cargo test --no-default-features`, and a coverage run. Make one of them fail, read the
   message, and fix it.
5. **Make a build-vs-depend call.** Find one dependency in `Cargo.toml`, and argue (in a
   paragraph) whether we should have built it ourselves instead. There's no single right
   answer — the *reasoning* is the skill.

---

## The one-sentence version

Vibe coding well is **disciplined delegation**: you own intent, real-data validation, and
honesty; the agent owns the typing — and the loop between you, repeated in small steps with
proof at every step, is what turns "vibes" into a crate you'd stake your name on.

---

## Version history

- **v1.1** — 2026-06-08 — Added the multi-volume (sliced) ground-truth example: a passing synthetic suite, then a real 52 GB extraction that caught two bugs.
- **v1.0** — 2026-06-08 — First complete edition.

---

© 2026 Albert Hui. *The techniques and ideas here are yours to apply freely; the prose of this tutorial is not licensed for republication without permission.*
