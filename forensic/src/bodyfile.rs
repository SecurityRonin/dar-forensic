//! Sleuth Kit [`bodyfile`](https://wiki.sleuthkit.org/index.php?title=Body_file)
//! formatting — the pipe-delimited input format for TSK's `mactime` timeline
//! tool, as emitted by `fls -m`.
//!
//! One line per entry:
//! `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`. DAR records no
//! content hash, inode address, or birth time, so those fields are `0`.

use crate::{DarEntry, EntryKind};

/// TSK type letter for an entry kind (used for both the name-type and
/// metadata-type positions of the mode string, which agree here).
fn type_letter(kind: EntryKind) -> char {
    match kind {
        // A hardlink resolves to a regular file's data.
        EntryKind::File | EntryKind::Hardlink => 'r',
        EntryKind::Directory => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::NamedPipe => 'p',
        EntryKind::Socket => 's',
        EntryKind::CharDevice => 'c',
        EntryKind::BlockDevice => 'b',
        EntryKind::Unknown(_) => '-',
    }
}

/// The 9-character symbolic permission string (`rwxr-xr-x`), applying the
/// setuid/setgid/sticky conventions (`s`/`S` on the user/group execute slots,
/// `t`/`T` on the other-execute slot).
fn perm_string(mode: u16) -> String {
    const RWX: [char; 3] = ['r', 'w', 'x'];
    let mut s: [char; 9] = ['-'; 9];
    for (i, slot) in s.iter_mut().enumerate() {
        if mode & (1 << (8 - i)) != 0 {
            *slot = RWX[i % 3];
        }
    }
    // setuid (0o4000) / setgid (0o2000) on the owner/group execute slots, and
    // the sticky bit (0o1000) on the other-execute slot. Lowercase when the
    // underlying execute bit is also set, uppercase when it is not.
    if mode & 0o4000 != 0 {
        s[2] = if s[2] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        s[5] = if s[5] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        s[8] = if s[8] == 'x' { 't' } else { 'T' };
    }
    s.iter().collect()
}

/// Escape a name for the pipe-delimited line: backslash and pipe are
/// backslash-escaped, and control bytes (`< 0x20` or `0x7f`) become `\xNN` so a
/// crafted name with an embedded newline or pipe cannot forge extra lines or
/// fields.
fn escape_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                const HEX: [u8; 16] = *b"0123456789abcdef";
                let b = c as u32;
                out.push('\\');
                out.push('x');
                // The guard restricts `b` to <= 0x7f, so each nibble is in
                // 0..16 and the table index is always in bounds — panic-free.
                out.push(HEX[((b >> 4) & 0xf) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out
}

/// One TSK 3.x bodyfile line (no trailing newline) for `entry`.
pub(crate) fn line(entry: &DarEntry) -> String {
    let t = type_letter(entry.kind);
    let mode = format!("{t}/{t}{}", perm_string(entry.mode));

    let mut name = escape_name(&entry.path_lossy());
    if let Some(target) = &entry.symlink_target {
        name.push_str(" -> ");
        name.push_str(&escape_name(&String::from_utf8_lossy(target)));
    }

    // DAR has no content hash (field 1), no inode address (field 3), and no
    // birth time (crtime); ctime is absent before format 8.
    let ctime = entry.ctime.unwrap_or(0);
    format!(
        "0|{name}|0|{mode}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|0",
        uid = entry.uid,
        gid = entry.gid,
        size = entry.size,
        atime = entry.atime,
        mtime = entry.mtime,
    )
}
