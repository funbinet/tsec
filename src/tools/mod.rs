//! Tool registry — builds the master list of all ten TSEC phases.

pub mod types;
pub mod phase01_reconnaissance;
pub mod phase02_attack_surface;
pub mod phase03_vulnerability;
pub mod phase04_payload;
pub mod phase05_privesc;
pub mod phase06_credentials;
pub mod phase07_lateral;
pub mod phase08_persistence;
pub mod phase09_objectives;
pub mod phase10_wireless;

use types::Category;

pub const PHASE01: Category = Category { name: "Reconnaissance", tools: phase01_reconnaissance::TOOLS };
pub const PHASE02: Category = Category { name: "Attack Surface Mapping", tools: phase02_attack_surface::TOOLS };
pub const PHASE03: Category = Category { name: "Vulnerability Assessment", tools: phase03_vulnerability::TOOLS };
pub const PHASE04: Category = Category { name: "Payload Development", tools: phase04_payload::TOOLS };
pub const PHASE05: Category = Category { name: "Privilege Escalation", tools: phase05_privesc::TOOLS };
pub const PHASE06: Category = Category { name: "Credential Access", tools: phase06_credentials::TOOLS };
pub const PHASE07: Category = Category { name: "Lateral Movement", tools: phase07_lateral::TOOLS };
pub const PHASE08: Category = Category { name: "Persistence & Evasion", tools: phase08_persistence::TOOLS };
pub const PHASE09: Category = Category { name: "Actions on Objectives", tools: phase09_objectives::TOOLS };
pub const PHASE10: Category = Category { name: "Wireless Hacking", tools: phase10_wireless::TOOLS };

/// Returns all ten TSEC phases in display order.
pub fn build_registry() -> Vec<&'static Category> {
    vec![
        &PHASE01,
        &PHASE02,
        &PHASE03,
        &PHASE04,
        &PHASE05,
        &PHASE06,
        &PHASE07,
        &PHASE08,
        &PHASE09,
        &PHASE10,
    ]
}
