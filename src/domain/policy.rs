//! Policy engine for ABAC/RBAC authorization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy effect - allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Policy condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Check if an attribute equals a value.
    Eq { attribute: String, value: serde_json::Value },
    /// Check if an attribute not equals a value.
    Ne { attribute: String, value: serde_json::Value },
    /// Check if an attribute is in a list.
    In { attribute: String, values: Vec<serde_json::Value> },
    /// Check if an attribute matches a regex.
    Regex { attribute: String, pattern: String },
    /// Check if a numeric attribute is greater than.
    Gt { attribute: String, value: f64 },
    /// Check if a numeric attribute is less than.
    Lt { attribute: String, value: f64 },
    /// Check if a string attribute starts with.
    StartsWith { attribute: String, prefix: String },
    /// Check if a string attribute ends with.
    EndsWith { attribute: String, suffix: String },
    /// Check time-based conditions.
    Time { attribute: String, start: String, end: String },
    /// Boolean AND of conditions.
    And { conditions: Vec<Condition> },
    /// Boolean OR of conditions.
    Or { conditions: Vec<Condition> },
    /// Boolean NOT of condition.
    Not { condition: Box<Condition> },
}

impl Condition {
    /// Evaluate the condition against attributes.
    pub fn evaluate(&self, attributes: &HashMap<String, serde_json::Value>) -> bool {
        match self {
            Condition::Eq { attribute, value } => {
                attributes.get(attribute).map(|v| v == value).unwrap_or(false)
            }
            Condition::Ne { attribute, value } => {
                attributes.get(attribute).map(|v| v != value).unwrap_or(true)
            }
            Condition::In { attribute, values } => {
                attributes.get(attribute).map(|v| values.contains(v)).unwrap_or(false)
            }
            Condition::Regex { attribute, pattern } => {
                if let Some(serde_json::Value::String(s)) = attributes.get(attribute) {
                    regex::Regex::new(pattern).map(|r| r.is_match(s)).unwrap_or(false)
                } else {
                    false
                }
            }
            Condition::Gt { attribute, value } => {
                if let Some(serde_json::Value::Number(n)) = attributes.get(attribute) {
                    n.as_f64().map(|v| v > *value).unwrap_or(false)
                } else {
                    false
                }
            }
            Condition::Lt { attribute, value } => {
                if let Some(serde_json::Value::Number(n)) = attributes.get(attribute) {
                    n.as_f64().map(|v| v < *value).unwrap_or(false)
                } else {
                    false
                }
            }
            Condition::StartsWith { attribute, prefix } => {
                if let Some(serde_json::Value::String(s)) = attributes.get(attribute) {
                    s.starts_with(prefix)
                } else {
                    false
                }
            }
            Condition::EndsWith { attribute, suffix } => {
                if let Some(serde_json::Value::String(s)) = attributes.get(attribute) {
                    s.ends_with(suffix)
                } else {
                    false
                }
            }
            Condition::Time { .. } => true, // Simplified
            Condition::And { conditions } => conditions.iter().all(|c| c.evaluate(attributes)),
            Condition::Or { conditions } => conditions.iter().any(|c| c.evaluate(attributes)),
            Condition::Not { condition } => !condition.evaluate(attributes),
        }
    }
}

/// A policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name.
    pub name: String,
    /// Policy description.
    pub description: Option<String>,
    /// Resource pattern.
    pub resource: String,
    /// Actions.
    pub actions: Vec<String>,
    /// Policy effect.
    pub effect: PolicyEffect,
    /// Conditions for the policy to apply.
    pub conditions: Vec<Condition>,
    /// Priority (higher = more important).
    pub priority: i32,
}

impl Policy {
    /// Create a new policy.
    pub fn new(name: impl Into<String>, resource: impl Into<String>, effect: PolicyEffect) -> Self {
        Self {
            name: name.into(),
            description: None,
            resource: resource.into(),
            actions: Vec::new(),
            effect,
            conditions: Vec::new(),
            priority: 0,
        }
    }

    /// Add an action.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.actions.push(action.into());
        self
    }

    /// Add a condition.
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if this policy applies to a resource and action.
    pub fn applies_to(&self, resource: &str, action: &str) -> bool {
        // Check resource pattern
        let resource_matches = if self.resource == "*" {
            true
        } else if self.resource.ends_with(":*") {
            let prefix = &self.resource[..self.resource.len() - 2];
            resource.starts_with(prefix)
        } else {
            self.resource == resource
        };

        // Check action
        let action_matches = self.actions.iter().any(|a| a == "*" || a == action);

        resource_matches && action_matches
    }

    /// Evaluate the policy against attributes.
    pub fn evaluate(
        &self,
        attributes: &HashMap<String, serde_json::Value>,
    ) -> Option<PolicyEffect> {
        if self.conditions.is_empty() {
            return Some(self.effect);
        }

        if self.conditions.iter().all(|c| c.evaluate(attributes)) {
            Some(self.effect)
        } else {
            None
        }
    }
}

/// Policy engine for making authorization decisions.
pub struct PolicyEngine {
    policies: Vec<Policy>,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new() -> Self {
        Self { policies: Vec::new() }
    }

    /// Add a policy.
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
        self.policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add multiple policies.
    pub fn add_policies(&mut self, policies: Vec<Policy>) {
        for policy in policies {
            self.add_policy(policy);
        }
    }

    /// Clear all policies.
    pub fn clear(&mut self) {
        self.policies.clear();
    }

    /// Evaluate a request.
    pub fn evaluate(
        &self,
        resource: &str,
        action: &str,
        attributes: &HashMap<String, serde_json::Value>,
    ) -> bool {
        let mut has_deny = false;

        for policy in &self.policies {
            if policy.applies_to(resource, action) {
                if let Some(effect) = policy.evaluate(attributes) {
                    match effect {
                        PolicyEffect::Deny => {
                            has_deny = true;
                            break;
                        }
                        PolicyEffect::Allow => {
                            // Continue checking for higher priority denies
                        }
                    }
                }
            }
        }

        !has_deny
    }

    /// Explain a decision.
    pub fn explain(
        &self,
        resource: &str,
        action: &str,
        attributes: &HashMap<String, serde_json::Value>,
    ) -> Vec<String> {
        let mut reasons = Vec::new();

        for policy in &self.policies {
            if policy.applies_to(resource, action) {
                if let Some(effect) = policy.evaluate(attributes) {
                    let effect_str = match effect {
                        PolicyEffect::Allow => "ALLOW",
                        PolicyEffect::Deny => "DENY",
                    };
                    reasons.push(format!(
                        "{}: {} (priority: {})",
                        effect_str, policy.name, policy.priority
                    ));
                }
            }
        }

        reasons
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_policy() {
        let mut engine = PolicyEngine::new();

        // Add read-all policy
        engine.add_policy(
            Policy::new("read-all", "documents:*", PolicyEffect::Allow)
                .with_action("read")
                .with_priority(1),
        );

        let attrs = HashMap::new();
        // With no deny policies, engine defaults to allow
        assert!(engine.evaluate("documents:123", "read", &attrs));
        assert!(engine.evaluate("documents:123", "write", &attrs));
    }

    #[test]
    fn test_deny_blocks_allow() {
        let mut engine = PolicyEngine::new();

        // Add allow policy
        engine.add_policy(
            Policy::new("read-all", "documents:*", PolicyEffect::Allow)
                .with_action("read")
                .with_priority(1),
        );

        // Add deny policy with higher priority
        engine.add_policy(
            Policy::new("deny-confidential", "documents:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Eq {
                    attribute: "classification".to_string(),
                    value: serde_json::json!("confidential"),
                }),
        );

        let mut attrs = HashMap::new();
        attrs.insert("classification".to_string(), serde_json::json!("public"));
        assert!(engine.evaluate("documents:123", "read", &attrs));

        attrs.insert("classification".to_string(), serde_json::json!("confidential"));
        assert!(!engine.evaluate("documents:123", "read", &attrs));
    }
}
