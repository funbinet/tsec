//! Strongly typed identifiers used across the catalog, planner and reports.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::fmt;

/// Zero-based index of a phase inside the authoritative phase set.
///
/// The phase *set* is fixed: it comes from the framework's ten-phase model and
/// is never invented or removed at runtime. `PhaseIndex` only encodes ordering
/// and display position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhaseIndex(pub u8);

impl PhaseIndex {
    /// One-based phase number as shown to the operator.
    pub fn number(self) -> u8 {
        self.0 + 1
    }
}

impl fmt::Display for PhaseIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PHASE {}", self.number())
    }
}

/// Stable dotted identifier of a capability, e.g. `recon.subdomain-discovery`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityId(String);

impl CapabilityId {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Filesystem-safe form used for artifact directories.
    pub fn slug(&self) -> String {
        self.0.replace('.', "-")
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable identifier of a provider (a concrete external tool integration).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Index of a task inside an execution plan. Execution order is always
/// deterministic: tasks are scheduled in ascending `TaskId` order within a
/// dependency wave, and results are aggregated in ascending `TaskId` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub usize);

impl TaskId {
    pub fn index(self) -> usize {
        self.0
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{:02}", self.0 + 1)
    }
}

/// Identifier for one framework run: `YYYYMMDD_HHMMSS_<discriminator>`.
///
/// The discriminator is derived from the start time and the process id, so two
/// runs started in the same second on the same host still get distinct,
/// reproducible-looking directories without pulling in a random source.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RunId {
    id: String,
    stamp: String,
}

impl RunId {
    pub fn new(raw: impl Into<String>) -> Self {
        let id: String = raw.into();
        let mut split = id.splitn(3, '_');
        let date = split.next().unwrap_or("");
        let time = split.next().unwrap_or("");
        let mut stamp = String::with_capacity(date.len() + time.len() + 1);
        if !date.is_empty() {
            stamp.push_str(date);
            if !time.is_empty() {
                stamp.push('_');
                stamp.push_str(time);
            }
        }
        Self { id, stamp }
    }

    /// Build an identifier for a run starting now.
    pub fn now() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let pid = std::process::id();
        Self::new(format!("{stamp}_{:02x}{:02x}", pid & 0xff, n & 0xff))
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// `YYYYMMDD_HHMMSS` portion, used to build artifact filenames.
    pub fn stamp(&self) -> &str {
        &self.stamp
    }

    pub fn short(&self) -> &str {
        self.id.split('_').nth(2).unwrap_or("00")
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_index_is_one_based_for_display() {
        assert_eq!(PhaseIndex(0).number(), 1);
        assert_eq!(PhaseIndex(9).number(), 10);
        assert_eq!(PhaseIndex(0).to_string(), "PHASE 1");
    }

    #[test]
    fn task_id_displays_one_based() {
        assert_eq!(TaskId(0).to_string(), "T01");
        assert_eq!(TaskId(11).to_string(), "T12");
    }

    #[test]
    fn run_id_splits_stamp_and_short() {
        let r = RunId::new("20260929_143012_7f");
        assert_eq!(r.stamp(), "20260929_143012");
        assert_eq!(r.short(), "7f");
    }

    #[test]
    fn capability_slug_is_path_safe() {
        assert_eq!(
            CapabilityId::new("recon.subdomain-discovery").slug(),
            "recon-subdomain-discovery"
        );
    }
}
