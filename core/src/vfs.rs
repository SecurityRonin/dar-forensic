//! `impl FileSystem for DarVfs` — the forensic-vfs adapter (behind the `vfs`
//! feature) so a DAR archive's file tree composes as `Arc<dyn FileSystem>` in the
//! forensic-vfs engine, like the ISO 9660 / UDF adapters.
//!
//! [`DarVfs`] wraps a parsed [`DarReader`] plus a content cache in a `Mutex`, so
//! every read is `&self` over interior mutability and one mounted handle serves N
//! workers (matching the iso9660/udf adapters — [`DarReader::extract`] takes
//! `&mut self`, which the `Mutex` provides). Nodes are addressed by
//! [`FileId::Opaque`] carrying an index into an internal node vector built at
//! [`DarVfs::open`] — DAR's catalogue is a flat list of full `/`-separated paths,
//! so the directory tree is derived by splitting those paths and a synthetic root
//! (node 0) is seeded for the archive's top level.
//!
//! ## Mapping notes / known limits
//! - **FsKind.** `forensic-vfs`'s `FsKind` has no DAR/archive variant (it is
//!   `#[non_exhaustive]`, and this crate must not add one), so
//!   [`FileSystem::kind`] reports [`FsKind::Other`].
//! - **Sector sizes.** A DAR archive is a byte stream with no media geometry;
//!   [`FileSystem::sector_sizes`] reports 512 for all three fields (a neutral
//!   default, not a real on-media block).
//! - **Times.** DAR records real Unix-epoch atime/mtime/ctime per entry, so
//!   [`FsMeta::times`] is populated (`modified`/`accessed`, and `changed` when the
//!   format records ctime); `born` is `None` (DAR stores no creation time).
//!   Epoch is UTC-anchored, so [`FileSystem::timestamp_zone`] is
//!   [`TimeZonePolicy::Utc`].
//! - **Single stream.** A DAR entry has one data stream; a non-`Default`
//!   [`StreamId`] is refused loud.
//! - **Extents (first cut).** An archive exposes no on-media allocation runs, so
//!   [`FileSystem::extents`] yields a single logical run (`image_offset` = 0,
//!   `len` = the entry's uncompressed size) rather than true on-disk runs.
//!   Surfacing the archive's stored offset/length is future work.
//! - **Deleted/unallocated (first cut).** DAR carving of orphaned catalogue
//!   entries and free-space enumeration are not yet surfaced, so
//!   [`FileSystem::deleted`]/[`FileSystem::unallocated`] are empty streams. Future
//!   work, not fabricated data.

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem,
    FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy, VfsError,
    VfsResult,
};

use crate::{DarEntry, DarError, DarReader, EntryKind};

/// A neutral logical block size for an archive byte stream (no media geometry).
const ARCHIVE_BLOCK: u32 = 512;

/// One node in the derived directory tree. The synthetic root is node 0 (`path`
/// `None`); every catalogue entry becomes a node carrying its full archive path.
struct Node {
    /// Full `/`-separated archive path (raw bytes); `None` only for the synthetic
    /// root. Used verbatim as the [`DarReader::extract`] key.
    path: Option<Vec<u8>>,
    /// Last path component (raw bytes) — the name a parent lists this child under.
    name: Vec<u8>,
    kind: NodeKind,
    size: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    atime: i64,
    mtime: i64,
    ctime: Option<i64>,
    symlink_target: Option<Vec<u8>>,
    /// Node ids of this node's directory children.
    children: Vec<u64>,
}

/// Reader plus its per-entry decompressed-content cache, guarded by one mutex.
struct Inner<R: Read + Seek> {
    reader: DarReader<R>,
    /// Node id → the entry's fully-decompressed bytes (extraction is not free, and
    /// `read_at` may be called repeatedly at different offsets).
    cache: HashMap<u64, Arc<Vec<u8>>>,
}

/// A mounted DAR archive exposed through the forensic-vfs `FileSystem` contract.
/// Reads are `&self` over an interior `Mutex`, so one handle serves N workers.
pub struct DarVfs<R: Read + Seek> {
    inner: Mutex<Inner<R>>,
    nodes: Vec<Node>,
}

impl<R: Read + Seek + Send> DarVfs<R> {
    /// Open a DAR archive over a `Read + Seek` cursor.
    ///
    /// Parses the archive catalogue, then derives the directory tree from the flat
    /// list of full paths: a synthetic root (node 0) plus one node per entry, wired
    /// parent→children by splitting each path on `/`.
    pub fn open(reader: R) -> VfsResult<Self> {
        let reader = DarReader::open(reader).map_err(map_err)?;
        let entries = reader.entries();
        let nodes = build_tree(&entries);
        Ok(Self {
            inner: Mutex::new(Inner {
                reader,
                cache: HashMap::new(),
            }),
            nodes,
        })
    }

    /// Lock the interior state, recovering from a poisoned mutex rather than
    /// panicking (Paranoid Gatekeeper).
    fn lock(&self) -> MutexGuard<'_, Inner<R>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolve a [`FileId`] to a node, or a loud error for any non-`Opaque` id or
    /// an index outside the node table.
    fn node_of(&self, id: FileId) -> VfsResult<&Node> {
        let idx = index_of(id)?;
        self.nodes
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .ok_or(VfsError::Unsupported {
                layer: "dar file-id",
                scheme: format!("Opaque({idx}) out of range"),
            })
    }

    /// The fully-decompressed bytes of node `idx` (a file at archive `path`),
    /// extracting once and caching by node id so repeated `read_at` offsets do not
    /// re-decompress. A decode/IO failure is surfaced loud, never a silent empty.
    fn content(&self, idx: u64, path: &[u8]) -> VfsResult<Arc<Vec<u8>>> {
        let mut inner = self.lock();
        if let Some(data) = inner.cache.get(&idx) {
            return Ok(Arc::clone(data));
        }
        let bytes = inner.reader.extract(path).map_err(map_err)?;
        let arc = Arc::new(bytes);
        inner.cache.insert(idx, Arc::clone(&arc));
        Ok(arc)
    }
}

/// The node index carried by a [`FileId`]; any other identity domain is a caller
/// error surfaced loud.
fn index_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(n) => Ok(n),
        other => Err(VfsError::Unsupported {
            layer: "dar file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// A DAR entry exposes a single unnamed data stream; a named-stream id is refused
/// loud.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "dar stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Map a [`DarError`] to the VFS error type, keeping I/O distinct from a
/// structural decode failure.
fn map_err(e: DarError) -> VfsError {
    match e {
        DarError::Io(source) => VfsError::Io {
            op: "dar read",
            source,
        },
        DarError::NotADar => VfsError::Bootstrap {
            stage: "dar mount",
            detail: "not a DAR archive".to_string(),
        },
        other => VfsError::Decode {
            layer: "dar",
            offset: 0,
            detail: other.to_string(),
            bytes: forensic_vfs::SmallHex::new(&[]),
        },
    }
}

/// Map a DAR [`EntryKind`] to a VFS [`NodeKind`].
fn node_kind(kind: EntryKind) -> NodeKind {
    match kind {
        EntryKind::Directory => NodeKind::Dir,
        EntryKind::Symlink => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}

/// The last `/`-separated component of a raw path (the leaf name). A path with no
/// separator is its own name.
fn leaf(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(pos) => path.get(pos + 1..).unwrap_or(&[]).to_vec(),
        None => path.to_vec(),
    }
}

/// Map a Unix-epoch seconds timestamp to a VFS [`TimeStamp`].
fn to_timestamp(secs: i64) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(secs) * 1_000_000_000,
        source: TimeSource::Unspecified,
        resolution: TimeResolution::Seconds,
    }
}

/// Derive the directory tree (node 0 = synthetic root) from the flat catalogue of
/// full `/`-separated paths. Every entry becomes a node; parent→children links are
/// resolved by full-path prefix. An entry whose parent directory was not itself
/// listed is attached to the root so it is never lost.
fn build_tree(entries: &[DarEntry]) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::with_capacity(entries.len() + 1);
    // Node 0: synthetic root.
    nodes.push(Node {
        path: None,
        name: Vec::new(),
        kind: NodeKind::Dir,
        size: 0,
        uid: 0,
        gid: 0,
        mode: 0,
        atime: 0,
        mtime: 0,
        ctime: None,
        symlink_target: None,
        children: Vec::new(),
    });

    // Map each full path to its node id as we create nodes.
    let mut by_path: HashMap<Vec<u8>, u64> = HashMap::new();
    for e in entries {
        let id = nodes.len() as u64;
        by_path.insert(e.path.clone(), id);
        nodes.push(Node {
            path: Some(e.path.clone()),
            name: leaf(&e.path),
            kind: node_kind(e.kind),
            size: e.size,
            uid: u32::try_from(e.uid).unwrap_or(u32::MAX),
            gid: u32::try_from(e.gid).unwrap_or(u32::MAX),
            mode: e.mode,
            atime: e.atime,
            mtime: e.mtime,
            ctime: e.ctime,
            symlink_target: e.symlink_target.clone(),
            children: Vec::new(),
        });
    }

    // Wire parent→children by full-path prefix (the segment before the last '/').
    // Nodes were pushed in entry order after the synthetic root, so entry `i` is
    // node id `i + 1` — the child id is known by construction, no lookup needed.
    for (i, e) in entries.iter().enumerate() {
        let child = (i + 1) as u64;
        let parent_id = match e.path.iter().rposition(|&b| b == b'/') {
            Some(pos) => {
                let parent_path = e.path.get(..pos).unwrap_or(&[]);
                by_path.get(parent_path).copied().unwrap_or(0)
            }
            None => 0,
        };
        if let Some(parent) = nodes.get_mut(usize::try_from(parent_id).unwrap_or(usize::MAX)) {
            parent.children.push(child);
        }
    }
    nodes
}

impl<R: Read + Seek + Send> FileSystem for DarVfs<R> {
    fn kind(&self) -> FsKind {
        // forensic-vfs has no DAR/archive FsKind variant (see the module note).
        FsKind::Other
    }

    fn root(&self) -> FileId {
        FileId::Opaque(0)
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: ARCHIVE_BLOCK,
            physical: ARCHIVE_BLOCK,
            cluster_or_block: ARCHIVE_BLOCK,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // DAR stores Unix-epoch seconds, which are UTC-anchored.
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let node = self.node_of(ino)?;
        if node.kind != NodeKind::Dir {
            return Err(VfsError::Decode {
                layer: "dar",
                offset: 0,
                detail: format!("node {:?} is not a directory", index_of(ino)?),
                bytes: forensic_vfs::SmallHex::new(&[]),
            });
        }
        // Snapshot children into owned entries so the stream outlives the borrow.
        let mut out: Vec<VfsResult<VfsDirEntry>> = Vec::with_capacity(node.children.len());
        for &child in &node.children {
            let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) else {
                continue; // cov:unreachable: children hold in-range node ids by construction
            };
            out.push(Ok(VfsDirEntry {
                name: c.name.clone(),
                id: FileId::Opaque(child),
                kind: c.kind,
            }));
        }
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let node = self.node_of(ino)?;
        require_default_stream(stream)?;
        // First cut: an archive exposes no on-media runs, so a non-empty file
        // yields one logical run (image_offset 0). See the module note.
        if node.size == 0 {
            return Ok(ExtentStream::empty());
        }
        let run = RunInfo {
            run: ByteRun {
                image_offset: 0,
                len: node.size,
                flags: RunFlags::default(),
            },
            alloc: RunAlloc::Allocated,
        };
        Ok(ExtentStream::new(std::iter::once(Ok(run))))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let node = self.node_of(parent)?;
        if node.kind != NodeKind::Dir {
            return Err(VfsError::Decode {
                layer: "dar",
                offset: 0,
                detail: format!("node {:?} is not a directory", index_of(parent)?),
                bytes: forensic_vfs::SmallHex::new(&[]),
            });
        }
        for &child in &node.children {
            if let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) {
                if c.name == name {
                    return Ok(Some(FileId::Opaque(child)));
                }
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let idx = index_of(ino)?;
        let node = self.node_of(ino)?;
        Ok(FsMeta {
            ino: idx,
            kind: node.kind,
            allocated: Allocation::Allocated,
            size: node.size,
            nlink: 1,
            uid: Some(node.uid),
            gid: Some(node.gid),
            mode: Some(u32::from(node.mode)),
            times: MacbTimes {
                modified: Some(to_timestamp(node.mtime)),
                accessed: Some(to_timestamp(node.atime)),
                changed: node.ctime.map(to_timestamp),
                // DAR records no creation time; honestly absent, not epoch-0.
                born: None,
            },
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: node.symlink_target.clone(),
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let idx = index_of(ino)?;
        require_default_stream(stream)?;
        // Validate the node exists / is a file; a directory (or the root) has no
        // extractable data and reads as 0.
        let (kind, path) = {
            let node = self.node_of(ino)?;
            (node.kind, node.path.clone())
        };
        if kind != NodeKind::File {
            return Ok(0);
        }
        let Some(path) = path else {
            return Ok(0);
        };
        let data = self.content(idx, &path)?;
        // An offset that overflows usize (only possible on a <64-bit target)
        // saturates to usize::MAX, which is past any real length, so the EOF
        // check below reads it as 0 — no separate, untestable overflow arm.
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        if start >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - start).min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(start..start + n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let node = self.node_of(ino)?;
        match &node.symlink_target {
            Some(target) => {
                let n = target.len().min(cap);
                Ok(target.get(..n).unwrap_or(&[]).to_vec())
            }
            // A non-symlink (or a symlink with no recorded target) reads as an
            // empty target, matching the iso9660/udf adapters.
            None => Ok(Vec::new()),
        }
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The committed real `v11_hello.dar` fixture (dar 2.8.5, format 11.3): a
    /// single `files/hello.txt` = `"hello corpus\n"` (13 bytes). See
    /// `tests/data/README.md`.
    const V11_HELLO: &[u8] = include_bytes!("../../tests/data/v11_hello.dar");
    const HELLO_CONTENT: &[u8] = b"hello corpus\n";

    fn open_hello() -> DarVfs<Cursor<Vec<u8>>> {
        DarVfs::open(Cursor::new(V11_HELLO.to_vec())).expect("open v11_hello.dar")
    }

    /// Walk from the root to `files/hello.txt`, returning its FileId.
    fn hello_id(fs: &DarVfs<Cursor<Vec<u8>>>) -> FileId {
        let files = fs
            .lookup(fs.root(), b"files")
            .expect("lookup files")
            .expect("files dir present");
        fs.lookup(files, b"hello.txt")
            .expect("lookup hello.txt")
            .expect("hello.txt present")
    }

    #[test]
    fn kind_root_and_zone() {
        let fs = open_hello();
        assert_eq!(fs.kind(), FsKind::Other);
        assert!(matches!(fs.root(), FileId::Opaque(0)));
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
        let ss = fs.sector_sizes();
        assert_eq!(ss.logical, 512);
        assert_eq!(ss.cluster_or_block, 512);
        assert!(ss.physical >= 512);
        // root() is resolvable via meta as a directory.
        let m = fs.meta(fs.root()).expect("root meta");
        assert_eq!(m.kind, NodeKind::Dir);
    }

    #[test]
    fn lists_root_and_reaches_files_dir() {
        let fs = open_hello();
        let names: Vec<Vec<u8>> = fs
            .read_dir(fs.root())
            .expect("read_dir root")
            .map(|e| e.expect("entry").name)
            .collect();
        assert!(
            names.iter().any(|n| n == b"files"),
            "root should list the 'files' directory, got {names:?}"
        );
        let files = fs
            .lookup(fs.root(), b"files")
            .expect("lookup")
            .expect("files");
        assert_eq!(fs.meta(files).expect("meta files").kind, NodeKind::Dir);
    }

    #[test]
    fn reads_hello_content_and_meta() {
        let fs = open_hello();
        let id = hello_id(&fs);
        let m = fs.meta(id).expect("meta hello");
        assert_eq!(m.kind, NodeKind::File);
        assert_eq!(m.size, HELLO_CONTENT.len() as u64);
        assert_eq!(m.allocated, Allocation::Allocated);
        // DAR records a real mtime.
        assert!(m.times.modified.is_some(), "DAR stores mtime");
        assert!(m.times.born.is_none(), "DAR stores no creation time");

        let mut buf = [0u8; 64];
        let n = fs
            .read_at(id, StreamId::Default, 0, &mut buf)
            .expect("read_at");
        assert_eq!(&buf[..n], HELLO_CONTENT);
    }

    #[test]
    fn read_at_content_matches_extract() {
        // Self-consistency: the adapter's read_at yields the same bytes as the
        // reader's own extract() for the same path.
        let fs = open_hello();
        let id = hello_id(&fs);
        let mut whole = Vec::new();
        let mut off = 0u64;
        loop {
            let mut buf = [0u8; 8];
            let n = fs
                .read_at(id, StreamId::Default, off, &mut buf)
                .expect("read_at");
            if n == 0 {
                break;
            }
            whole.extend_from_slice(&buf[..n]);
            off += n as u64;
        }
        let extracted = fs
            .lock()
            .reader
            .extract(b"files/hello.txt")
            .expect("extract");
        assert_eq!(whole, extracted);
        assert_eq!(whole, HELLO_CONTENT);
    }

    #[test]
    fn read_at_with_offset_and_past_eof() {
        let fs = open_hello();
        let id = hello_id(&fs);
        let mut buf = [0u8; 8];
        let n = fs
            .read_at(id, StreamId::Default, 6, &mut buf)
            .expect("read");
        assert_eq!(&buf[..n], b"corpus\n");
        // reading past EOF yields 0
        assert_eq!(
            fs.read_at(id, StreamId::Default, 9999, &mut buf)
                .expect("eof"),
            0
        );
    }

    #[test]
    fn root_extents_and_hello_extents() {
        let fs = open_hello();
        // root is a dir with no data -> at most a single logical run
        let root_runs: Vec<_> = fs
            .extents(fs.root(), StreamId::Default)
            .expect("root extents")
            .map(|r| r.expect("run"))
            .collect();
        assert!(root_runs.len() <= 1);

        let id = hello_id(&fs);
        let runs: Vec<_> = fs
            .extents(id, StreamId::Default)
            .expect("extents")
            .map(|r| r.expect("run"))
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run.len, HELLO_CONTENT.len() as u64);
        assert_eq!(runs[0].alloc, RunAlloc::Allocated);
    }

    #[test]
    fn empty_forensic_surfaces() {
        let fs = open_hello();
        assert_eq!(fs.deleted().unwrap().count(), 0);
        assert_eq!(fs.unallocated().unwrap().count(), 0);
        let id = hello_id(&fs);
        assert!(fs.read_link(id, 4096).unwrap().is_empty());
    }

    #[test]
    fn read_dir_on_a_file_is_loud() {
        let fs = open_hello();
        let id = hello_id(&fs);
        assert!(fs.read_dir(id).is_err());
    }

    #[test]
    fn wrong_file_id_and_stream_are_loud() {
        let fs = open_hello();
        // A non-Opaque FileId is not a DAR node id.
        assert!(fs.meta(FileId::NtfsRef { entry: 5, seq: 1 }).is_err());
        assert!(fs.read_dir(FileId::NtfsRef { entry: 5, seq: 1 }).is_err());
        assert!(fs
            .lookup(FileId::NtfsRef { entry: 5, seq: 1 }, b"x")
            .is_err());
        assert!(fs
            .read_link(FileId::NtfsRef { entry: 5, seq: 1 }, 8)
            .is_err());
        // An out-of-range node index is refused.
        assert!(fs.meta(FileId::Opaque(9_999_999)).is_err());
        // A named stream is refused.
        let id = hello_id(&fs);
        assert!(fs
            .read_at(id, StreamId::Named(1), 0, &mut [0u8; 4])
            .is_err());
        assert!(fs.extents(id, StreamId::Named(1)).is_err());
    }

    #[test]
    fn lookup_missing_is_none() {
        let fs = open_hello();
        assert!(fs.lookup(fs.root(), b"NOPE.NOTPRESENT").unwrap().is_none());
    }

    #[test]
    fn index_of_rejects_non_opaque() {
        assert!(super::index_of(FileId::Opaque(42)).is_ok());
        assert!(super::index_of(FileId::NtfsRef { entry: 1, seq: 1 }).is_err());
    }

    #[test]
    fn leaf_splits_on_last_separator() {
        assert_eq!(super::leaf(b"files/hello.txt"), b"hello.txt");
        assert_eq!(super::leaf(b"toplevel"), b"toplevel");
        assert_eq!(super::leaf(b"a/b/c"), b"c");
    }

    #[test]
    fn map_err_maps_io_bootstrap_and_decode() {
        let io = super::map_err(DarError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        )));
        assert!(matches!(io, VfsError::Io { op: "dar read", .. }));

        let boot = super::map_err(DarError::NotADar);
        assert!(matches!(
            boot,
            VfsError::Bootstrap {
                stage: "dar mount",
                ..
            }
        ));

        let decode = super::map_err(DarError::Corrupt("boom".into()));
        assert!(matches!(decode, VfsError::Decode { layer: "dar", .. }));
    }

    #[test]
    fn node_kind_maps_directory_symlink_and_other() {
        assert_eq!(super::node_kind(EntryKind::Directory), NodeKind::Dir);
        assert_eq!(super::node_kind(EntryKind::Symlink), NodeKind::Symlink);
        assert_eq!(super::node_kind(EntryKind::File), NodeKind::File);
    }

    #[test]
    fn lookup_on_a_file_is_loud() {
        let fs = open_hello();
        let id = hello_id(&fs);
        assert!(fs.lookup(id, b"anything").is_err());
    }

    #[test]
    fn read_at_on_a_directory_reads_zero() {
        let fs = open_hello();
        let files = fs.lookup(fs.root(), b"files").unwrap().unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            fs.read_at(files, StreamId::Default, 0, &mut buf).unwrap(),
            0
        );
    }

    /// A blank node of the given kind — a test-only builder for exercising the
    /// defensive guards a well-formed catalogue can never trigger.
    fn blank_node(kind: NodeKind) -> Node {
        Node {
            path: None,
            name: Vec::new(),
            kind,
            size: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            atime: 0,
            mtime: 0,
            ctime: None,
            symlink_target: None,
            children: Vec::new(),
        }
    }

    #[test]
    fn dangling_child_id_is_skipped_not_panicked() {
        // A directory whose child id points past the node table is a state
        // build_tree never emits; read_dir and lookup must skip it defensively
        // rather than panic on the out-of-range index.
        let mut fs = open_hello();
        let bad = fs.nodes.len() as u64;
        let mut dir = blank_node(NodeKind::Dir);
        dir.path = Some(b"bad".to_vec());
        dir.name = b"bad".to_vec();
        dir.children = vec![9_999_999];
        fs.nodes.push(dir);
        let id = FileId::Opaque(bad);
        assert_eq!(fs.read_dir(id).unwrap().count(), 0);
        assert!(fs.lookup(id, b"whatever").unwrap().is_none());
    }

    #[test]
    fn file_node_without_a_path_reads_zero() {
        // A File node with no recorded path cannot arise from a parsed catalogue
        // (every entry node carries its path); the guard reads it as 0.
        let mut fs = open_hello();
        let ghost = fs.nodes.len() as u64;
        let mut node = blank_node(NodeKind::File);
        node.size = 8; // non-zero size, still no path
        fs.nodes.push(node);
        let mut buf = [0u8; 8];
        assert_eq!(
            fs.read_at(FileId::Opaque(ghost), StreamId::Default, 0, &mut buf)
                .unwrap(),
            0
        );
    }

    #[test]
    fn read_link_returns_recorded_target_and_honors_cap() {
        let mut fs = open_hello();
        let sym = fs.nodes.len() as u64;
        let mut node = blank_node(NodeKind::Symlink);
        node.path = Some(b"link".to_vec());
        node.name = b"link".to_vec();
        node.symlink_target = Some(b"/etc/passwd".to_vec());
        fs.nodes.push(node);
        let id = FileId::Opaque(sym);
        assert_eq!(fs.read_link(id, 4096).unwrap(), b"/etc/passwd");
        // cap truncates the returned target
        assert_eq!(fs.read_link(id, 4).unwrap(), b"/etc");
    }
}
