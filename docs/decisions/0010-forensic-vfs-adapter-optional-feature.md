# 10. Expose a `forensic-vfs` `FileSystem` adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's *VFS & Universal Container Abstraction* policy says a consumer that
reads an evidence image must not know one container/filesystem format from
another: filesystems over a byte source implement the `forensic-vfs` traits, and
`forensic-vfs-engine` composes concrete decoders so a whole stack reads as one
`Arc<dyn ImageSource>`/`Arc<dyn FileSystem>`. A DAR archive is a logical file
tree — the same shape the engine already mounts for ISO 9660 / UDF — so it should
compose the same way rather than forcing each consumer to special-case DAR.

But `forensic-vfs` is an extra dependency that a bare parser consumer does not
want, and it is the KNOWLEDGE-leaf contract crate (still `0.1`).

## Decision

Provide `impl FileSystem for DarVfs` in `core/src/vfs.rs`, gated behind an
**optional `vfs` Cargo feature** (`core/Cargo.toml`: `vfs =
["dep:forensic-vfs"]`, `forensic-vfs` declared `optional = true`; commits
`087f4f0` RED / `ae8dfe9` GREEN). `DarVfs` wraps a parsed `DarReader` plus a
content cache in a `Mutex` so every read is `&self` over interior mutability and
one mounted handle serves N workers — matching the iso9660/udf adapters. Nodes
are addressed by `FileId::Opaque` indices into a node vector built at
`DarVfs::open`; the flat catalogue of `/`-separated paths is split into a
directory tree with a synthetic root.

Honest mapping limits are documented in the module header, not faked:
`FsKind::Other` (no archive variant in the `#[non_exhaustive]` enum, which this
crate must not extend), neutral 512-byte sector sizes, `born = None` (DAR records
no creation time), a single logical extent, and empty `deleted`/`unallocated`
streams (DAR carving is future work, not fabricated data).

## Consequences

- A DAR archive composes into the universal container abstraction like any other
  filesystem — `forensic-vfs-engine` can mount an archive without a DAR-specific
  branch in the consumer.
- The bare `dar-core` reader stays dependency-light: consumers who do not enable
  `vfs` never pull `forensic-vfs`.
- Because `forensic-vfs` is `0.1` and `forensic-vfs-engine` is `publish = false`,
  cross-repo composition still uses a path/registry dep until they stabilise —
  the adapter is ready ahead of the engine's publish.
- Extents and deleted/unallocated enumeration are explicitly first-cut and empty
  rather than approximated, keeping the adapter honest about what it does not yet
  surface.
