//! dar-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use dar_forensic::{Anomaly, AnomalyKind};
use forensicnomicon::report::{Observation, Source};

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = Anomaly::new(AnomalyKind::IncompleteCatalog {
        entries_recovered: 3,
    });
    let f = a.to_finding(Source {
        analyzer: "dar-forensic".to_string(),
        scope: "DAR".to_string(),
        version: None,
    });
    assert!(!f.code.is_empty());
    assert!(f.severity.is_some());
    assert_eq!(f.source.analyzer, "dar-forensic");
}
