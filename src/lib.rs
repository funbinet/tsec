//! TSEC — Tactical Security Enumeration & Compromise Framework.
//!
//! A target-driven enumeration and post-exploitation framework built around ten
//! fixed phases. This crate is the library half: configuration, the capability
//! catalog, provider verification, the domain model, the execution engine and
//! the theme. The `tsec` binary is a thin front end over it.
//!
//! # The idea
//!
//! An operator picks a *capability* — "PORT DISCOVERY", "TEMPLATE SCAN" — not a
//! tool. The catalog (`catalog/capabilities.toml`) says which providers
//! implement that capability and exactly how each is invoked. Nothing about a
//! tool's flags is written in Rust, and nothing in the catalog is trusted until
//! `scripts/verify_catalog.py` has checked every flag against that tool's own
//! help output.
//!
//! # Guarantees the code is written to keep
//!
//! * **Verified syntax only.** A provider is offered only when its executable
//!   resolves and its help output documents the flags in use. See
//!   [`provider`].
//! * **No shell, ever.** Commands are argument vectors. A template containing
//!   `|`, `>` or `&&` is rejected at load time rather than quietly mis-executed.
//!   See [`catalog`].
//! * **Oniux is the network boundary, not a feature.** Every network-capable
//!   task is launched as `oniux <tool> <args…>`, inside a private namespace
//!   whose only route is Tor. If oniux is missing or cannot establish its
//!   environment the task fails; there is no direct-network fallback, no
//!   anonymity toggle, and no per-tool opt-out. See [`exec`].
//! * **Secrets stay out of the evidence.** Sensitive arguments are masked in
//!   every rendering, record and report. See [`domain::command`].
//! * **Honest unavailability.** A capability whose tools are not installed is
//!   reported unavailable with a reason, never silently offered and never
//!   substituted. See [`catalog::Capability::unavailable_reason`].

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod catalog;
pub mod config;
pub mod domain;
pub mod error;
pub mod exec;
pub mod parser;
pub mod provider;
pub mod store;
pub mod ui;

pub use catalog::{Capability, Catalog, Operation, PHASES};
pub use config::Config;
pub use error::{Result, TsecError};
pub use provider::Registry;

/// Framework version, from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
