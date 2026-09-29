//! Findings, evidence and provenance.
//!
//! A *finding* is a single normalised fact that some tool actually reported.
//! The framework never invents one: every finding carries a [`Provenance`]
//! pointing at the provider, command, timestamp and artifact it came from, so
//! the operator can always verify the framework's interpretation against the
//! preserved raw evidence.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Classification of a harvested fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Category {
    /// The operator's stated target.
    Target,
    /// A hostname or subdomain.
    Host,
    /// An IP address.
    Ip,
    /// A port number.
    Port,
    /// A named service.
    Service,
    /// A software or product version.
    Version,
    /// A detected technology or product.
    Technology,
    /// An HTTP(S) URL.
    Url,
    /// A specific API or administrative endpoint.
    Endpoint,
    /// A DNS record value.
    Dns,
    /// An HTTP status/header/title observation.
    Http,
    /// A TLS or certificate observation.
    Tls,
    /// A security finding raised by a scanning tool.
    Finding,
    /// Verbatim evidence retained from the raw stream.
    Evidence,
    /// A credential artefact (hash, ticket, username).
    Credential,
    /// Descriptive metadata about the tool or the run.
    Metadata,
    /// An error or diagnostic emitted by a tool.
    Error,
}

impl Category {
    /// Capitalised section heading used in the consolidated harvest.
    pub fn heading(self) -> &'static str {
        match self {
            Category::Target => "TARGET",
            Category::Host => "HOSTS",
            Category::Ip => "IP ADDRESSES",
            Category::Port => "PORTS",
            Category::Service => "SERVICES",
            Category::Version => "VERSIONS",
            Category::Technology => "TECHNOLOGIES",
            Category::Url => "URLS",
            Category::Endpoint => "ENDPOINTS",
            Category::Dns => "DNS RECORDS",
            Category::Http => "HTTP OBSERVATIONS",
            Category::Tls => "TLS OBSERVATIONS",
            Category::Finding => "FINDINGS",
            Category::Evidence => "EVIDENCE",
            Category::Credential => "CREDENTIALS",
            Category::Metadata => "METADATA",
            Category::Error => "ERRORS",
        }
    }

    /// Presentation order in the consolidated harvest: high-signal first.
    pub fn order(self) -> u8 {
        match self {
            Category::Finding => 0,
            Category::Credential => 1,
            Category::Target => 2,
            Category::Host => 3,
            Category::Url => 4,
            Category::Endpoint => 5,
            Category::Ip => 6,
            Category::Port => 7,
            Category::Service => 8,
            Category::Version => 9,
            Category::Technology => 10,
            Category::Dns => 11,
            Category::Http => 12,
            Category::Tls => 13,
            Category::Evidence => 14,
            Category::Metadata => 15,
            Category::Error => 16,
        }
    }
}

/// Where a piece of harvested information came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub provider: String,
    pub operation: String,
    pub task_id: String,
    /// Exact command that produced the information.
    pub command: String,
    pub observed_at: DateTime<Utc>,
    /// Raw evidence file backing this information.
    pub artifact: PathBuf,
    /// The network boundary the producing task ran behind.
    ///
    /// Part of provenance rather than presentation: a finding harvested from a
    /// local hash audit and one harvested through oniux are not the same claim,
    /// and the harvest must not silently present them as though they were.
    pub boundary: crate::domain::execution::ExecBoundary,
}

/// One normalised, traceable piece of harvested information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub category: Category,
    /// The value as the tool reported it, unchanged.
    pub value: String,
    /// Optional structured attribute, e.g. `port 443/tcp on 10.0.0.1`.
    pub detail: Option<String>,
    pub provenance: Provenance,
    /// Number of times this value was observed across the run.
    pub occurrences: usize,
}

impl Provenance {
    /// Placeholder used while a harvest is being assembled, before it is
    /// attributed to the task that produced it.
    pub fn placeholder() -> Self {
        Self {
            provider: String::new(),
            operation: String::new(),
            task_id: String::new(),
            command: String::new(),
            observed_at: Utc::now(),
            artifact: PathBuf::new(),
            boundary: crate::domain::execution::ExecBoundary::Local,
        }
    }
}

impl Finding {
    /// Identity used for deduplication: category plus value, case-folded.
    pub fn dedup_key(&self) -> (Category, String) {
        (self.category, self.value.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov() -> Provenance {
        Provenance {
            boundary: crate::domain::execution::ExecBoundary::Oniux,
            provider: "httpx".into(),
            operation: "probe".into(),
            task_id: "T02".into(),
            command: "httpx -l ports.txt -silent".into(),
            observed_at: Utc::now(),
            artifact: PathBuf::from("/out/raw/httpx-probe.jsonl"),
        }
    }

    #[test]
    fn headings_are_uppercase_plural_labels() {
        assert_eq!(Category::Host.heading(), "HOSTS");
        assert_eq!(Category::Technology.heading(), "TECHNOLOGIES");
    }

    #[test]
    fn findings_sort_high_signal_first() {
        let mut cats = vec![Category::Evidence, Category::Finding, Category::Host];
        cats.sort_by_key(|c| c.order());
        assert_eq!(
            cats,
            vec![Category::Finding, Category::Host, Category::Evidence]
        );
    }

    #[test]
    fn dedup_key_is_case_insensitive_but_keeps_value() {
        let a = Finding {
            category: Category::Host,
            value: "API.Example.com".into(),
            detail: None,
            provenance: prov(),
            occurrences: 1,
        };
        let b = Finding {
            category: Category::Host,
            value: "api.example.com".into(),
            detail: Some("seen twice".into()),
            provenance: prov(),
            occurrences: 1,
        };
        assert_eq!(a.dedup_key(), b.dedup_key());
        assert_ne!(a.value, b.value);
    }
}
