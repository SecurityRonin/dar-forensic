//! DAR forensic findings: severity, anomaly classification, and the analysis
//! result returned by [`DarAudit::audit`](crate::DarAudit::audit).
//!
//! Mirrors the sibling forensic crates (e.g. `iso9660-forensic`): every
//! anomaly's severity, stable machine-readable code, and human-readable note are
//! *derived* from its [`AnomalyKind`], so they cannot drift. A disk-forensic
//! orchestrator can aggregate these uniformly with findings from the partition
//! and other filesystem layers.
//!
//! An anomaly is an *observation*, never an assertion of intent: the notes say
//! "consistent with …", and the examiner draws the conclusions.

use core::fmt;

/// The canonical 5-level severity scale, shared across every `SecurityRonin`
/// analyzer via [`forensicnomicon::report`]. Ordered
/// `Info < Low < Medium < High < Critical`.
pub use forensicnomicon::report::Severity;

impl forensicnomicon::report::Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
}

/// Classification of a DAR forensic anomaly.
///
/// Each variant carries the evidence needed to reproduce the observation. The
/// suspicious/benign framing lives in [`AnomalyKind::note`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AnomalyKind {
    /// Catalogue parsing stopped before a clean root end-of-directory — the
    /// listing may be truncated. Consistent with a partial/damaged archive or an
    /// entry type this reader does not model (parsing stops loudly rather than
    /// silently returning a short listing).
    IncompleteCatalog {
        /// Number of entries recovered before parsing stopped.
        entries_recovered: usize,
    },

    /// An entry's path is absolute (begins with `/`). DAR stores paths relative
    /// to the archive root, so an absolute path is unusual; on naive extraction
    /// it would write outside the destination directory. Consistent with an
    /// archive crafted to overwrite system paths.
    AbsolutePath {
        /// The absolute path (lossy UTF-8).
        path: String,
    },

    /// An entry's path contains a `..` parent-directory component. On naive
    /// extraction this could escape the destination directory — a path-traversal
    /// ("zip-slip") vector.
    ParentTraversal {
        /// The traversing path (lossy UTF-8).
        path: String,
    },

    /// More than one catalogue entry records the same path. Consistent with a
    /// crafted archive in which a later entry shadows an earlier one on
    /// extraction (the examiner sees one name but two sets of bytes).
    DuplicatePath {
        /// The duplicated path (lossy UTF-8).
        path: String,
    },

    /// An entry timestamp lies implausibly far in the future (beyond the year
    /// 2100). Consistent with a misconfigured clock on the archiving host or
    /// with timestamp tampering.
    FutureTimestamp {
        /// Path of the entry (lossy UTF-8).
        path: String,
        /// Which timestamp: `atime`, `mtime`, or `ctime`.
        field: &'static str,
        /// The timestamp, seconds since the Unix epoch.
        epoch_secs: i64,
    },

    /// An entry's name contains non-printable control bytes (below `0x20`, or
    /// `0x7f`). Consistent with an attempt to obscure the true filename in
    /// terminal listings (e.g. an embedded escape sequence or carriage return).
    ControlCharsInName {
        /// The name as lossy UTF-8 (control bytes become U+FFFD on display).
        path: String,
    },
}

impl AnomalyKind {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            // A truncated catalogue means entries may be missing entirely.
            AnomalyKind::IncompleteCatalog { .. } => Severity::High,
            // Extraction-safety irregularities.
            AnomalyKind::AbsolutePath { .. } | AnomalyKind::ParentTraversal { .. } => {
                Severity::Medium
            }
            // Listing irregularities with common benign explanations.
            AnomalyKind::DuplicatePath { .. }
            | AnomalyKind::FutureTimestamp { .. }
            | AnomalyKind::ControlCharsInName { .. } => Severity::Low,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::IncompleteCatalog { .. } => "DAR-CATALOG-INCOMPLETE",
            AnomalyKind::AbsolutePath { .. } => "DAR-PATH-ABSOLUTE",
            AnomalyKind::ParentTraversal { .. } => "DAR-PATH-TRAVERSAL",
            AnomalyKind::DuplicatePath { .. } => "DAR-PATH-DUPLICATE",
            AnomalyKind::FutureTimestamp { .. } => "DAR-TIME-FUTURE",
            AnomalyKind::ControlCharsInName { .. } => "DAR-NAME-CONTROL",
        }
    }

    /// Human-readable description (observation, not a conclusion).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::IncompleteCatalog { entries_recovered } => format!(
                "catalogue parsing stopped after recovering {entries_recovered} entries, before a \
                 clean root end-of-directory — the listing may be truncated; consistent with a \
                 partial or damaged archive, or an entry type this reader does not model"
            ),
            AnomalyKind::AbsolutePath { path } => format!(
                "entry `{path}` has an absolute path — DAR stores paths relative to the archive \
                 root, so on naive extraction this would write outside the destination directory; \
                 consistent with an archive crafted to overwrite system paths"
            ),
            AnomalyKind::ParentTraversal { path } => format!(
                "entry `{path}` contains a `..` parent-directory component — on naive extraction \
                 this could escape the destination directory (a path-traversal / 'zip-slip' vector)"
            ),
            AnomalyKind::DuplicatePath { path } => format!(
                "path `{path}` is recorded by more than one catalogue entry — consistent with a \
                 crafted archive in which a later entry shadows an earlier one on extraction"
            ),
            AnomalyKind::FutureTimestamp { path, field, epoch_secs } => format!(
                "entry `{path}` {field} is {epoch_secs} (beyond the year 2100) — implausibly far in \
                 the future; consistent with a misconfigured clock or timestamp tampering"
            ),
            AnomalyKind::ControlCharsInName { path } => format!(
                "entry `{path}` contains non-printable control byte(s) in its name — consistent \
                 with an attempt to obscure the true filename in a terminal listing"
            ),
        }
    }
}

/// A single forensic anomaly: an [`AnomalyKind`] with its derived severity,
/// stable code, and human-readable note.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind` so they
    /// cannot drift from the classification.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.note)
    }
}
