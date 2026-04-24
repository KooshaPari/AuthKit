//! Phenotype Policy Engine - RBAC/ABAC policy enforcement
//!
//! Supports role-based and attribute-based access control with
//! async evaluation and caching.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use phenotype_error_core::ErrorCode;

/// Policy engine error types
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy evaluation failed: {reason}")]
    EvaluationFailed { reason: String },

    #[error("Unknown policy: {policy_id}")]
    UnknownPolicy { policy_id: String },

    #[error("Invalid policy definition: {reason}")]
    InvalidDefinition { reason: String },

    #[error("Policy expired at {expired_at}")]
    PolicyExpired { expired_at: DateTime<Utc> },

    #[error("Circular policy dependency detected")]
    CircularDependency,
}

impl PolicyError {
    pub fn code(&self) -> ErrorCode {
        ErrorCode::PolicyViolation
    }
}

/// Subject performing the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub id: String,
    pub roles: Vec<String>,
    pub attributes: HashMap<String, AttributeValue>,
}

impl Subject {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            roles: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Resource being accessed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub kind: String,
    pub owner: Option<String>,
    pub attributes: HashMap<String, AttributeValue>,
}

impl Resource {
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            owner: None,
            attributes: HashMap::new(),
        }
    }

    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }
}

/// Action being performed
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    List,
    Execute,
    Custom(String),
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Create => write!(f, "create"),
            Action::Read => write!(f, "read"),
            Action::Update => write!(f, "update"),
            Action::Delete => write!(f, "delete"),
            Action::List => write!(f, "list"),
            Action::Execute => write!(f, "execute"),
            Action::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Attribute value for ABAC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    Number(f64),
    Bool(bool),
    Array(Vec<AttributeValue>),
    Object(HashMap<String, AttributeValue>),
}

impl From<&str> for AttributeValue {
    fn from(s: &str) -> Self {
        AttributeValue::String(s.to_string())
    }
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        AttributeValue::String(s)
    }
}

impl From<i64> for AttributeValue {
    fn from(n: i64) -> Self {
        AttributeValue::Number(n as f64)
    }
}

impl From<bool> for AttributeValue {
    fn from(b: bool) -> Self {
        AttributeValue::Bool(b)
    }
}

/// Context for policy evaluation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub timestamp: DateTime<Utc>,
    pub environment: HashMap<String, AttributeValue>,
    pub request_metadata: HashMap<String, AttributeValue>,
}

impl EvaluationContext {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            environment: HashMap::new(),
            request_metadata: HashMap::new(),
        }
    }

    pub fn with_env_var(
        mut self,
        key: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }
}

/// Policy decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub description: Option<String>,
    pub version: u32,
    pub effect: Decision,
    pub subjects: Vec<PolicySubject>,
    pub resources: Vec<PolicyResource>,
    pub actions: Vec<Action>,
    pub conditions: Vec<Condition>,
    pub priority: i32,
}

/// Policy subject matcher
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PolicySubject {
    Any,
    Role { role: String },
    User { user_id: String },
    Attribute { key: String, value: AttributeValue },
}

/// Policy resource matcher
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PolicyResource {
    Any,
    Kind { kind: String },
    Id { id: String },
    OwnedBy { owner_id: String },
    Attribute { key: String, value: AttributeValue },
}

/// Condition for fine-grained control
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Condition {
    /// Time-based condition
    TimeRange {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    /// IP address range
    IpRange { allowed: Vec<String> },
    /// Custom attribute condition
    Attribute {
        entity: EntityType,
        key: String,
        op: ComparisonOp,
        value: AttributeValue,
    },
    /// Rate limiting
    RateLimit {
        max_requests: u32,
        window_seconds: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityType {
    Subject,
    Resource,
    Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
}

/// Policy engine trait
#[async_trait]
pub trait PolicyEngine: Send + Sync + 'static {
    /// Evaluate a single policy
    async fn evaluate(
        &self,
        subject: &Subject,
        action: Action,
        resource: &Resource,
        ctx: &EvaluationContext,
    ) -> Result<Decision, PolicyError>;

    /// Evaluate all applicable policies and return aggregate decision
    async fn evaluate_all(
        &self,
        subject: &Subject,
        action: Action,
        resource: &Resource,
        ctx: &EvaluationContext,
    ) -> Result<Decision, PolicyError>;

    /// Add a policy
    async fn add_policy(&self, policy: Policy) -> Result<(), PolicyError>;

    /// Remove a policy
    async fn remove_policy(&self, policy_id: &str) -> Result<(), PolicyError>;

    /// Get all policies
    async fn list_policies(&self) -> Result<Vec<Policy>, PolicyError>;
}

/// In-memory policy engine implementation
pub struct InMemoryPolicyEngine {
    policies: DashMap<String, Policy>,
    evaluation_cache: DashMap<String, (Decision, DateTime<Utc>)>,
    cache_ttl_seconds: u64,
}

impl InMemoryPolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
            evaluation_cache: DashMap::new(),
            cache_ttl_seconds: 60,
        }
    }

    pub fn with_cache_ttl(mut self, seconds: u64) -> Self {
        self.cache_ttl_seconds = seconds;
        self
    }

    fn make_cache_key(&self, subject: &Subject, action: &Action, resource: &Resource) -> String {
        format!(
            "{}:{}:{}:{}",
            subject.id, action, resource.id, resource.kind
        )
    }

    fn matches_subject(policy_subject: &PolicySubject, subject: &Subject) -> bool {
        match policy_subject {
            PolicySubject::Any => true,
            PolicySubject::Role { role } => subject.has_role(role),
            PolicySubject::User { user_id } => subject.id == *user_id,
            PolicySubject::Attribute { key, value } => subject.attributes.get(key) == Some(value),
        }
    }

    fn matches_resource(policy_resource: &PolicyResource, resource: &Resource) -> bool {
        match policy_resource {
            PolicyResource::Any => true,
            PolicyResource::Kind { kind } => resource.kind == *kind,
            PolicyResource::Id { id } => resource.id == *id,
            PolicyResource::OwnedBy { owner_id } => resource.owner.as_ref() == Some(owner_id),
            PolicyResource::Attribute { key, value } => resource.attributes.get(key) == Some(value),
        }
    }

    fn evaluate_condition(
        condition: &Condition,
        _subject: &Subject,
        _resource: &Resource,
        ctx: &EvaluationContext,
    ) -> bool {
        match condition {
            Condition::TimeRange { start, end } => {
                let now = Utc::now();
                now >= *start && now <= *end
            }
            Condition::IpRange { allowed } => {
                // Simplified - in production would parse and check CIDR ranges
                allowed.iter().any(|ip| !ip.is_empty())
            }
            Condition::Attribute {
                entity,
                key,
                op,
                value,
            } => {
                let actual = match entity {
                    EntityType::Environment => ctx.environment.get(key),
                    _ => None,
                };
                Self::compare(actual, op, value)
            }
            Condition::RateLimit {
                max_requests,
                window_seconds,
            } => {
                // Simplified - would track actual request counts
                *max_requests > 0 && *window_seconds > 0
            }
        }
    }

    fn compare(
        actual: Option<&AttributeValue>,
        op: &ComparisonOp,
        expected: &AttributeValue,
    ) -> bool {
        match (actual, op) {
            (Some(actual), ComparisonOp::Eq) => actual == expected,
            (Some(actual), ComparisonOp::Ne) => actual != expected,
            (None, ComparisonOp::Eq) => false,
            (None, ComparisonOp::Ne) => true,
            _ => false,
        }
    }
}

impl Default for InMemoryPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyEngine for InMemoryPolicyEngine {
    async fn evaluate(
        &self,
        subject: &Subject,
        action: Action,
        resource: &Resource,
        ctx: &EvaluationContext,
    ) -> Result<Decision, PolicyError> {
        let cache_key = self.make_cache_key(subject, &action, resource);

        // Check cache
        if let Some(cached) = self.evaluation_cache.get(&cache_key) {
            let (decision, timestamp) = cached.value();
            let elapsed = Utc::now().signed_duration_since(*timestamp).num_seconds();
            if elapsed < self.cache_ttl_seconds as i64 {
                return Ok(*decision);
            }
        }

        // Find matching policies
        let matching: Vec<_> = self
            .policies
            .iter()
            .filter(|entry| {
                let policy = entry.value();

                // Check action
                let action_matches = policy
                    .actions
                    .iter()
                    .any(|a| *a == action || *a == Action::Custom("*".to_string()));

                // Check subject
                let subject_matches = policy
                    .subjects
                    .iter()
                    .any(|s| Self::matches_subject(s, subject));

                // Check resource
                let resource_matches = policy
                    .resources
                    .iter()
                    .any(|r| Self::matches_resource(r, resource));

                action_matches && subject_matches && resource_matches
            })
            .map(|entry| entry.value().clone())
            .collect();

        // Sort by priority (higher first)
        let mut sorted = matching;
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Evaluate conditions and determine decision
        let mut decision = Decision::Deny; // Default deny

        for policy in sorted {
            let conditions_met = policy
                .conditions
                .iter()
                .all(|c| Self::evaluate_condition(c, subject, resource, ctx));

            if conditions_met {
                decision = policy.effect;
                if decision == Decision::Deny {
                    // Deny takes precedence
                    break;
                }
            }
        }

        // Cache result
        self.evaluation_cache
            .insert(cache_key, (decision, Utc::now()));

        Ok(decision)
    }

    async fn evaluate_all(
        &self,
        subject: &Subject,
        action: Action,
        resource: &Resource,
        ctx: &EvaluationContext,
    ) -> Result<Decision, PolicyError> {
        self.evaluate(subject, action, resource, ctx).await
    }

    async fn add_policy(&self, policy: Policy) -> Result<(), PolicyError> {
        self.policies.insert(policy.id.clone(), policy);
        Ok(())
    }

    async fn remove_policy(&self, policy_id: &str) -> Result<(), PolicyError> {
        self.policies.remove(policy_id);
        Ok(())
    }

    async fn list_policies(&self) -> Result<Vec<Policy>, PolicyError> {
        Ok(self
            .policies
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }
}

/// RBAC (Role-Based Access Control) helper
pub struct RbacPolicyBuilder {
    policies: Vec<Policy>,
}

impl RbacPolicyBuilder {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn allow_role(
        mut self,
        role: impl Into<String>,
        resource_kind: impl Into<String>,
        actions: Vec<Action>,
    ) -> Self {
        let role = role.into();
        let resource_kind = resource_kind.into();
        let policy = Policy {
            id: format!("rbac:{}:role:{}", resource_kind, role),
            description: Some(format!("Allow {} role to perform actions", role)),
            version: 1,
            effect: Decision::Allow,
            subjects: vec![PolicySubject::Role { role }],
            resources: vec![PolicyResource::Kind {
                kind: resource_kind,
            }],
            actions,
            conditions: Vec::new(),
            priority: 100,
        };
        self.policies.push(policy);
        self
    }

    pub fn deny_role(
        mut self,
        role: impl Into<String>,
        resource_kind: impl Into<String>,
        actions: Vec<Action>,
    ) -> Self {
        let role = role.into();
        let resource_kind_str = resource_kind.into();
        let policy = Policy {
            id: format!("rbac:{}:deny:role:{}", &resource_kind_str, &role),
            description: Some(format!("Deny {} role from performing actions", role)),
            version: 1,
            effect: Decision::Deny,
            subjects: vec![PolicySubject::Role { role }],
            resources: vec![PolicyResource::Kind {
                kind: resource_kind_str,
            }],
            actions,
            conditions: Vec::new(),
            priority: 200, // Higher priority than allows
        };
        self.policies.push(policy);
        self
    }

    pub fn build(self) -> Vec<Policy> {
        self.policies
    }
}

impl Default for RbacPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple permit-all policy for development
pub fn permit_all_policy() -> Policy {
    Policy {
        id: "permit-all".to_string(),
        description: Some("Allow all actions (development only)".to_string()),
        version: 1,
        effect: Decision::Allow,
        subjects: vec![PolicySubject::Any],
        resources: vec![PolicyResource::Any],
        actions: vec![
            Action::Create,
            Action::Read,
            Action::Update,
            Action::Delete,
            Action::List,
            Action::Execute,
        ],
        conditions: Vec::new(),
        priority: 0,
    }
}

/// Deny-all policy (secure default)
pub fn deny_all_policy() -> Policy {
    Policy {
        id: "deny-all".to_string(),
        description: Some("Deny all actions by default".to_string()),
        version: 1,
        effect: Decision::Deny,
        subjects: vec![PolicySubject::Any],
        resources: vec![PolicyResource::Any],
        actions: vec![
            Action::Create,
            Action::Read,
            Action::Update,
            Action::Delete,
            Action::List,
            Action::Execute,
        ],
        conditions: Vec::new(),
        priority: 999,
    }
}
