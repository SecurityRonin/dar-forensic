# 2. Publish the parser as `dar-core`, import it as `dar`

Date: 2026-07-24
Status: Accepted

## Context

The fleet's crate-naming grammar (constitution: *Crate naming grammar*, Pattern
A — single-format repo) is: a reader/analyzer repo publishes exactly two crates,
`<x>-core` (reader) + `<x>-forensic` (analyzer). For DAR the natural bare name is
`dar`.

Two facts constrain the name:

- The bare **`dar`** name on crates.io is an **empty placeholder** owned by a
  third party (documented in `README.md`, *What makes this different*: "the `dar`
  name on crates.io is an empty placeholder"). We cannot publish the reader as
  `dar`.
- A short, distinctive import path is still wanted so consumers write `use
  dar::…` rather than the noisier `use dar_core::…`. The grammar permits this
  when the bare name is an obscure/placeholder crate we can co-exist with safely:
  publish under `-core` but set `[lib] name` to the bare word.

## Decision

Publish the parser package as **`dar-core`** with **`[lib] name = "dar"`**
(`core/Cargo.toml`), so the crates.io package is `dar-core` while the import path
is `use dar::…`. The workspace keys the internal dependency accordingly:

```toml
dar = { version = "0.7.0", path = "core", package = "dar-core" }
```

(root `Cargo.toml`). The analyzer package is **`dar-forensic`** — the headline
crate name for the repo (`forensic/Cargo.toml`). Commit `8d292b6` established
this at the split.

## Consequences

- Consumers `cargo add dar-core` (or `dar-forensic`, which re-exports it) yet
  write `use dar::…` / `use dar_forensic::…` — the placeholder never blocks a
  clean import path.
- The two published names (`dar-core`, `dar-forensic`) are self-describing on
  crates.io: `dar` is a distinctive-enough token that the `-core`/`-forensic`
  suffixes read correctly without a longer prefix (contrast the generic-word
  `browser-forensic-*` case).
- Should the bare `dar` placeholder ever be reassigned to an unrelated
  functional crate, the import alias could collide; the `[lib] name` indirection
  is reversible (drop to `dar_core`) without changing the published package name.
