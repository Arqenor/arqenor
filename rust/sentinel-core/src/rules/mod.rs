pub mod engine;
pub mod lolbin;
pub mod network;
pub mod sigma;
pub mod sigma_condition;

use serde::{Deserialize, Serialize};

/// Un pattern de matching : supporte glob simple (* = n'importe quoi)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern(pub String);

impl Pattern {
    pub fn matches(&self, s: &str) -> bool {
        let p = self.0.to_lowercase();
        let s = s.to_lowercase();
        if p.starts_with('*') && p.ends_with('*') {
            let mid = &p[1..p.len()-1];
            s.contains(mid)
        } else if let Some(suffix) = p.strip_prefix('*') {
            s.ends_with(suffix)
        } else if p.ends_with('*') {
            s.starts_with(&p[..p.len()-1])
        } else {
            s == p
        }
    }
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
}

use crate::models::alert::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id:        &'static str,   // ex: "SENT-1001"
    pub attack_id: &'static str,   // ex: "T1059.001"
    pub severity:  Severity,
    pub title:     &'static str,
    pub condition: RuleCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    ProcessCreate {
        /// Correspond à l'image (chemin exe), ex: `*\\powershell.exe`
        image:   Option<Pattern>,
        /// Correspond à la cmdline
        cmdline: Option<Vec<Pattern>>,  // tous doivent matcher (AND)
        cmdline_any: Option<Vec<Pattern>>, // au moins un (OR)
        /// Parent image
        parent:  Option<Pattern>,
    },
    ProcessName {
        /// Nom exact du process (sans chemin)
        names: Vec<Pattern>,
    },
}
