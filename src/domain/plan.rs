//! Execution planning: a task graph built from capability steps.
//!
//! A capability is a *goal*; a plan is the concrete, ordered set of tool
//! invocations that accomplish it. Tasks carry explicit dependencies so a step
//! that consumes an earlier step's artifact is never launched prematurely,
//! while independent steps are free to run concurrently.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::Duration;

use crate::domain::command::Command;
use crate::domain::ids::TaskId;
use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};

/// Why a plan is invalid. Plans are validated at construction time so a
/// malformed catalog or dependency cycle can never reach the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError {
    pub reason: String,
}

impl PlanError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl From<PlanError> for TsecError {
    fn from(e: PlanError) -> Self {
        TsecError::new(
            Stage::Plan,
            ExecutionErrorKind::Catalog { reason: e.reason },
        )
    }
}

/// Where a task's captured evidence is written inside the capability's
/// artifact directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawArtifact {
    /// Path of the tool's primary output (stdout, or the tool's own file).
    pub primary: std::path::PathBuf,
    /// Path of the captured stderr stream.
    pub stderr: std::path::PathBuf,
}

/// A single tool invocation inside a plan.
#[derive(Debug, Clone)]
pub struct Task {
    pub id: TaskId,
    /// Provider identifier, e.g. `httpx`.
    pub provider: String,
    /// Operation identifier inside the provider, e.g. `probe`.
    pub operation: String,
    /// Operator-facing purpose, e.g. "HTTP probe of discovered ports".
    pub label: String,
    pub command: Command,
    pub timeout: Duration,
    /// Tasks that must complete successfully before this one may start.
    pub depends_on: Vec<TaskId>,
    pub artifacts: RawArtifact,
    /// Declaration index, used to keep ordering deterministic.
    pub order: usize,
}

impl Task {
    /// True when the task opens network connections and must therefore be
    /// launched inside a private oniux namespace whose only route is Tor.
    pub fn requires_network(&self) -> bool {
        self.command.network
    }
}

/// A validated, ordered execution plan.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    pub tasks: Vec<Task>,
}

impl ExecutionPlan {
    /// Build a plan from tasks, validating uniqueness of ids, existence of
    /// dependencies and absence of cycles.
    pub fn new(tasks: Vec<Task>) -> std::result::Result<Self, PlanError> {
        let mut seen: BTreeSet<TaskId> = BTreeSet::new();
        let mut by_id: HashMap<TaskId, &Task> = HashMap::new();
        for t in &tasks {
            if !seen.insert(t.id) {
                return Err(PlanError::new(format!("duplicate task id {}", t.id)));
            }
            by_id.insert(t.id, t);
        }
        for t in &tasks {
            for dep in &t.depends_on {
                if !seen.contains(dep) {
                    return Err(PlanError::new(format!(
                        "task {} depends on unknown task {}",
                        t.id, dep
                    )));
                }
                if *dep == t.id {
                    return Err(PlanError::new(format!("task {} depends on itself", t.id)));
                }
            }
        }
        Self::validate_acyclic(&tasks)?;
        Ok(Self { tasks })
    }

    fn validate_acyclic(tasks: &[Task]) -> std::result::Result<(), PlanError> {
        // Kahn's algorithm over the dependency edges.
        let mut indegree: HashMap<TaskId, usize> =
            tasks.iter().map(|t| (t.id, t.depends_on.len())).collect();
        let mut dependents: HashMap<TaskId, Vec<TaskId>> = HashMap::new();
        for t in tasks {
            for d in &t.depends_on {
                dependents.entry(*d).or_default().push(t.id);
            }
        }
        let mut ready: Vec<TaskId> = indegree
            .iter()
            .filter(|(_, &n)| n == 0)
            .map(|(id, _)| *id)
            .collect();
        ready.sort();
        let mut visited = 0usize;
        while let Some(id) = ready.pop() {
            visited += 1;
            if let Some(ds) = dependents.get(&id) {
                for d in ds {
                    if let Some(n) = indegree.get_mut(d) {
                        *n -= 1;
                        if *n == 0 {
                            ready.push(*d);
                        }
                    }
                }
            }
        }
        if visited != tasks.len() {
            return Err(PlanError::new("task dependency graph contains a cycle"));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Tasks in deterministic execution order (ascending `order`).
    pub fn ordered(&self) -> Vec<&Task> {
        let mut v: Vec<&Task> = self.tasks.iter().collect();
        v.sort_by_key(|t| t.order);
        v
    }

    /// Dependency waves: the first wave contains tasks with no dependencies;
    /// each subsequent wave contains tasks whose dependencies all live in
    /// earlier waves. Tasks inside a wave are independent and run concurrently.
    pub fn waves(&self) -> Vec<Vec<TaskId>> {
        let by_id: HashMap<TaskId, &Task> = self.tasks.iter().map(|t| (t.id, t)).collect();
        let mut depth: HashMap<TaskId, usize> = HashMap::new();
        for t in &self.tasks {
            depth.insert(t.id, self.depth_of(t.id, &by_id, &mut HashMap::new()));
        }
        let max_depth = depth.values().copied().max().unwrap_or(0);
        let mut waves = vec![Vec::new(); max_depth + 1];
        for t in &self.tasks {
            waves[depth[&t.id]].push(t.id);
        }
        for w in waves.iter_mut() {
            w.sort();
        }
        waves
    }

    fn depth_of(
        &self,
        id: TaskId,
        by_id: &HashMap<TaskId, &Task>,
        memo: &mut HashMap<TaskId, usize>,
    ) -> usize {
        if let Some(&d) = memo.get(&id) {
            return d;
        }
        let d = by_id
            .get(&id)
            .map(|t| {
                t.depends_on
                    .iter()
                    .map(|dep| self.depth_of(*dep, by_id, memo) + 1)
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        memo.insert(id, d);
        d
    }

    pub fn get(&self, id: TaskId) -> Option<&Task> {
        self.tasks.iter().find(|t| t.id == id)
    }

    /// Concurrency profile: how many tasks can run simultaneously at most.
    pub fn max_width(&self) -> usize {
        self.waves().into_iter().map(|w| w.len()).max().unwrap_or(0)
    }
}

/// Builder used by capabilities to declare tasks and wire their dependencies.
///
/// `task` hands back a plain `TaskId` rather than a borrow of the builder.
/// That keeps declaration sites readable — several tasks can be declared in one
/// statement and then linked — instead of forcing every task into its own
/// statement purely to satisfy the borrow checker.
#[derive(Debug, Default, Clone)]
pub struct PlanBuilder {
    drafts: Vec<Draft>,
}

#[derive(Debug, Clone)]
struct Draft {
    provider: String,
    operation: String,
    label: String,
    command: Command,
    timeout: Duration,
    /// Raw artifact name stem for this task.
    stem: String,
    /// Draft indices this task depends on.
    depends_on: Vec<usize>,
    /// Raw evidence format for the primary artifact.
    raw_ext: String,
}

impl PlanBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a task and return its identifier.
    pub fn task(
        &mut self,
        provider: &str,
        operation: &str,
        label: impl Into<String>,
        command: Command,
    ) -> TaskId {
        let stem = format!("{}-{}", provider, operation);
        self.drafts.push(Draft {
            provider: provider.to_string(),
            operation: operation.to_string(),
            label: label.into(),
            command,
            timeout: Duration::from_secs(0),
            stem,
            depends_on: Vec::new(),
            raw_ext: "txt".to_string(),
        });
        TaskId(self.drafts.len() - 1)
    }

    /// Override a declared task's timeout.
    pub fn set_timeout(&mut self, id: TaskId, d: Duration) -> &mut Self {
        if let Some(draft) = self.drafts.get_mut(id.index()) {
            draft.timeout = d;
        }
        self
    }

    /// Set the raw evidence extension for a declared task.
    pub fn set_raw_ext(&mut self, id: TaskId, ext: &str) -> &mut Self {
        if let Some(draft) = self.drafts.get_mut(id.index()) {
            draft.raw_ext = ext.to_string();
        }
        self
    }

    /// Override the artifact filename stem for a declared task.
    pub fn set_stem(&mut self, id: TaskId, stem: impl Into<String>) -> &mut Self {
        if let Some(draft) = self.drafts.get_mut(id.index()) {
            draft.stem = stem.into();
        }
        self
    }

    /// Declare that `id` consumes the artifacts of `dep`.
    pub fn depend_on(&mut self, id: TaskId, dep: TaskId) -> &mut Self {
        if let Some(draft) = self.drafts.get_mut(id.index()) {
            if !draft.depends_on.contains(&dep.index()) {
                draft.depends_on.push(dep.index());
            }
        }
        self
    }

    /// Declare that `id` consumes the artifacts of every task in `deps`.
    pub fn depend_on_all(&mut self, id: TaskId, deps: &[TaskId]) -> &mut Self {
        for d in deps {
            self.depend_on(id, *d);
        }
        self
    }

    pub fn build(self, raw_dir: &std::path::Path) -> std::result::Result<ExecutionPlan, PlanError> {
        let mut tasks = Vec::with_capacity(self.drafts.len());
        for (i, d) in self.drafts.iter().enumerate() {
            let id = TaskId(i);
            let mut depends_on: Vec<TaskId> = d.depends_on.iter().map(|dep| TaskId(*dep)).collect();
            depends_on.sort();
            depends_on.dedup();
            let artifacts = RawArtifact {
                primary: raw_dir.join(format!("{}.{}", d.stem, d.raw_ext)),
                stderr: raw_dir.join(format!("{}.stderr.txt", d.stem)),
            };
            tasks.push(Task {
                id,
                provider: d.provider.clone(),
                operation: d.operation.clone(),
                label: d.label.clone(),
                command: d.command.clone(),
                timeout: d.timeout,
                depends_on,
                artifacts,
                order: i,
            });
        }
        ExecutionPlan::new(tasks)
    }
}

/// Convenience for building a plan from a slice of prepared commands.
pub fn plan_from_commands(
    raw_dir: &std::path::Path,
    entries: Vec<(String, String, String, Command)>,
) -> Result<ExecutionPlan> {
    let mut b = PlanBuilder::new();
    for (provider, operation, label, cmd) in entries {
        b.task(&provider, &operation, label, cmd);
    }
    Ok(b.build(raw_dir)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::command::Command;

    fn task(b: &mut PlanBuilder, name: &str, network: bool) -> TaskId {
        b.task(
            name,
            "op",
            name,
            Command::new(name, vec![]).network(network),
        )
    }

    #[test]
    fn plan_rejects_duplicate_ids() {
        let mut tasks = Vec::new();
        for _ in 0..2 {
            tasks.push(Task {
                id: TaskId(0),
                provider: "a".into(),
                operation: "op".into(),
                label: "a".into(),
                command: Command::new("a", vec![]),
                timeout: Duration::from_secs(1),
                depends_on: vec![],
                artifacts: RawArtifact {
                    primary: "/tmp/a".into(),
                    stderr: "/tmp/a.err".into(),
                },
                order: 0,
            });
        }
        let err = ExecutionPlan::new(tasks).unwrap_err();
        assert!(err.to_string().contains("duplicate task id"));
    }

    #[test]
    fn plan_reports_dependency_cycles() {
        let mut b = PlanBuilder::new();
        let t0 = b.task("a", "op", "a", Command::new("a", vec![]));
        let t1 = b.task("b", "op", "b", Command::new("b", vec![]));
        b.depend_on(t0, t1);
        b.depend_on(t1, t0);
        let err = b.build(std::path::Path::new("/tmp")).unwrap_err();
        assert!(err.to_string().contains("cycle"), "got: {err}");
    }

    #[test]
    fn plan_rejects_unknown_dependency() {
        let tasks = vec![Task {
            id: TaskId(0),
            provider: "a".into(),
            operation: "op".into(),
            label: "a".into(),
            command: Command::new("a", vec![]),
            timeout: Duration::from_secs(1),
            depends_on: vec![TaskId(9)],
            artifacts: RawArtifact {
                primary: "/tmp/a".into(),
                stderr: "/tmp/a.err".into(),
            },
            order: 0,
        }];
        let err = ExecutionPlan::new(tasks).unwrap_err();
        assert!(err.to_string().contains("unknown task"));
    }

    #[test]
    fn plan_rejects_self_dependency() {
        let tasks = vec![Task {
            id: TaskId(0),
            provider: "a".into(),
            operation: "op".into(),
            label: "a".into(),
            command: Command::new("a", vec![]),
            timeout: Duration::from_secs(1),
            depends_on: vec![TaskId(0)],
            artifacts: RawArtifact {
                primary: "/tmp/a".into(),
                stderr: "/tmp/a.err".into(),
            },
            order: 0,
        }];
        let err = ExecutionPlan::new(tasks).unwrap_err();
        assert!(err.to_string().contains("itself"));
    }

    #[test]
    fn independent_tasks_land_in_one_wave() {
        let mut b = PlanBuilder::new();
        for n in ["a", "b", "c", "d", "e", "f"] {
            task(&mut b, n, true);
        }
        let plan = b.build(std::path::Path::new("/tmp/raw")).unwrap();
        let waves = plan.waves();
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 6);
        assert_eq!(plan.max_width(), 6);
    }

    #[test]
    fn a_capability_can_declare_ten_parallel_tasks() {
        let mut b = PlanBuilder::new();
        for n in 0..10 {
            task(&mut b, &format!("p{n}"), true);
        }
        let plan = b.build(std::path::Path::new("/tmp/raw")).unwrap();
        assert_eq!(plan.waves().len(), 1);
        assert_eq!(plan.max_width(), 10);
    }

    #[test]
    fn dependent_tasks_land_in_later_waves() {
        let mut b = PlanBuilder::new();
        let first = b.task(
            "naabu",
            "ports",
            "ports",
            Command::new("naabu", vec![]).network(true),
        );
        let second = b.task(
            "httpx",
            "probe",
            "probe",
            Command::new("httpx", vec![]).network(true),
        );
        let third = b.task(
            "nmap",
            "svc",
            "svc",
            Command::new("nmap", vec![]).network(true),
        );
        b.depend_on(second, first);
        b.depend_on(third, second);
        let plan = b.build(std::path::Path::new("/tmp/raw")).unwrap();
        let waves = plan.waves();
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![TaskId(0)]);
        assert_eq!(waves[1], vec![TaskId(1)]);
        assert_eq!(waves[2], vec![TaskId(2)]);
    }

    #[test]
    fn a_task_can_depend_on_several_upstream_tasks() {
        let mut b = PlanBuilder::new();
        let a = b.task(
            "naabu",
            "ports",
            "a",
            Command::new("naabu", vec![]).network(true),
        );
        let c = b.task(
            "naabu",
            "dns",
            "c",
            Command::new("naabu", vec![]).network(true),
        );
        let join = b.task(
            "httpx",
            "probe",
            "join",
            Command::new("httpx", vec![]).network(true),
        );
        b.depend_on_all(join, &[a, c]);
        let plan = b.build(std::path::Path::new("/tmp/raw")).unwrap();
        let waves = plan.waves();
        assert_eq!(waves[0].len(), 2);
        assert_eq!(waves[1], vec![TaskId(2)]);
    }

    #[test]
    fn duplicate_dependency_is_recorded_once() {
        let mut b = PlanBuilder::new();
        let a = b.task("a", "op", "a", Command::new("a", vec![]));
        let c = b.task("c", "op", "c", Command::new("c", vec![]));
        b.depend_on(c, a);
        b.depend_on(c, a);
        let plan = b.build(std::path::Path::new("/tmp/raw")).unwrap();
        assert_eq!(plan.tasks[1].depends_on, vec![TaskId(0)]);
    }

    #[test]
    fn artifacts_are_written_into_the_raw_directory() {
        let mut b = PlanBuilder::new();
        let t = b.task("httpx", "probe", "probe", Command::new("httpx", vec![]));
        b.set_raw_ext(t, "jsonl");
        let plan = b.build(std::path::Path::new("/run/raw")).unwrap();
        let t = &plan.tasks[0];
        assert!(t
            .artifacts
            .primary
            .to_string_lossy()
            .ends_with("httpx-probe.jsonl"));
        assert!(t
            .artifacts
            .stderr
            .to_string_lossy()
            .ends_with("httpx-probe.stderr.txt"));
    }

    #[test]
    fn timeouts_and_stems_can_be_overridden() {
        let mut b = PlanBuilder::new();
        let t = b.task("nmap", "svc", "svc", Command::new("nmap", vec![]));
        b.set_timeout(t, Duration::from_secs(42));
        b.set_stem(t, "custom-stem");
        let plan = b.build(std::path::Path::new("/tmp")).unwrap();
        assert_eq!(plan.tasks[0].timeout, Duration::from_secs(42));
        assert_eq!(
            plan.tasks[0].artifacts.primary,
            std::path::Path::new("/tmp/custom-stem.txt")
        );
        assert_eq!(
            plan.tasks[0].artifacts.stderr,
            std::path::Path::new("/tmp/custom-stem.stderr.txt")
        );
    }

    #[test]
    fn network_flag_is_preserved_on_the_task() {
        let mut b = PlanBuilder::new();
        task(&mut b, "net", true);
        task(&mut b, "local", false);
        let plan = b.build(std::path::Path::new("/tmp")).unwrap();
        assert!(plan.tasks[0].requires_network());
        assert!(!plan.tasks[1].requires_network());
    }

    #[test]
    fn ordered_returns_declaration_order() {
        let mut b = PlanBuilder::new();
        task(&mut b, "z", false);
        task(&mut b, "a", false);
        let plan = b.build(std::path::Path::new("/tmp")).unwrap();
        let names: Vec<_> = plan.ordered().iter().map(|t| t.provider.clone()).collect();
        assert_eq!(names, vec!["z".to_string(), "a".to_string()]);
    }
}
