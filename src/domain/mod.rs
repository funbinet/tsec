//! Domain model: pure, strongly typed data with no I/O and no presentation.
//!
//! Everything the framework knows about *what it is doing* lives here. The
//! execution engine, the parser pipeline, the store and the UI all agree on
//! these types, which keeps command data in its original technical form while
//! presentation layers are free to restyle structural labels.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

pub mod command;
pub mod execution;
pub mod finding;
pub mod ids;
pub mod input;
pub mod plan;
pub mod report;

pub use command::{Command, CommandError};
pub use execution::{ExecutionRecord, Outcome, TaskStatus};
pub use finding::{Category, Finding, Provenance};
pub use ids::{CapabilityId, PhaseIndex, ProviderId, RunId, TaskId};
pub use input::{InputSpec, InputType, InputValues, ValidationRule};
pub use plan::{plan_from_commands, ExecutionPlan, PlanBuilder, PlanError, RawArtifact, Task};
pub use report::{CapabilityReport, RunReport, TaskReport};
