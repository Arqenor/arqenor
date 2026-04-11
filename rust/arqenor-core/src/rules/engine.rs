use super::{DetectionRule, RuleCondition};
use crate::models::alert::Alert;
use chrono::Utc;
use uuid::Uuid;

/// Événement process minimal pour l'évaluation de règles
#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub image: String, // chemin complet
    pub name: String,  // nom du fichier
    pub cmdline: String,
    pub parent_image: Option<String>,
}

pub fn evaluate(rule: &DetectionRule, event: &ProcessEvent) -> Option<Alert> {
    let matched = match &rule.condition {
        RuleCondition::ProcessCreate {
            image,
            cmdline,
            cmdline_any,
            parent,
        } => {
            let image_ok = image
                .as_ref()
                .map(|p| p.matches(&event.image) || p.matches(&event.name))
                .unwrap_or(true);
            let cmdline_ok = cmdline
                .as_ref()
                .map(|patterns| patterns.iter().all(|p| p.matches(&event.cmdline)))
                .unwrap_or(true);
            let cmdline_any_ok = cmdline_any
                .as_ref()
                .map(|patterns| patterns.iter().any(|p| p.matches(&event.cmdline)))
                .unwrap_or(true);
            let parent_ok = parent
                .as_ref()
                .map(|p| {
                    event
                        .parent_image
                        .as_deref()
                        .map(|pi| p.matches(pi))
                        .unwrap_or(false)
                })
                .unwrap_or(true);
            image_ok && cmdline_ok && cmdline_any_ok && parent_ok
        }
        RuleCondition::ProcessName { names } => names.iter().any(|p| p.matches(&event.name)),
    };

    if !matched {
        return None;
    }

    Some(Alert {
        id: Uuid::new_v4(),
        severity: rule.severity.clone(),
        kind: "lolbin".to_string(),
        message: format!("{} — PID {} ({})", rule.title, event.pid, event.name),
        occurred_at: Utc::now(),
        metadata: std::collections::HashMap::from([
            ("pid".into(), event.pid.to_string()),
            ("image".into(), event.image.clone()),
            ("cmdline".into(), event.cmdline.clone()),
        ]),
        rule_id: Some(rule.id.to_string()),
        attack_id: Some(rule.attack_id.to_string()),
    })
}

/// Évalue toutes les règles contre un événement et retourne les alertes générées
pub fn evaluate_all(rules: &[DetectionRule], event: &ProcessEvent) -> Vec<Alert> {
    rules.iter().filter_map(|r| evaluate(r, event)).collect()
}
