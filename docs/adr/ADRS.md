# ADR 001: Type-Safe Business Identifiers (BID)

## Status: Accepted

## Context

In distributed systems, identifier confusion is a common source of bugs. Passing a user ID where an organization ID is expected can lead to security vulnerabilities or data corruption. Traditional string-based identifiers provide no compile-time guarantees.

Current approaches include:
- Simple strings: `user_id: String` - No type safety
- UUIDs: `user_id: Uuid` - Better uniqueness, still no type safety
- Separate wrapper types: `UserId(String)`, `OrgId(String)` - Verbose

## Decision

We will implement type-safe business identifiers using Rust's phantom types:

```rust
pub struct Bid<T> {
    value: String,
    _phantom: PhantomData<T>,
}

pub struct User;
pub struct Organization;
pub struct Project;

pub type UserId = Bid<User>;
pub type OrgId = Bid<Organization>;
pub type ProjectId = Bid<Project>;
```

## Consequences

### Positive

1. **Compile-time safety**: Cannot mix different ID types
2. **Zero runtime cost**: PhantomData has no size
3. **Ergonomics**: Same underlying type with different semantics
4. **Serialization**: Transparent to serde (just the string value)

### Negative

1. **Type complexity**: More types in the codebase
2. **Generic constraints**: Functions must specify type parameters
3. **Learning curve**: Team must understand phantom type pattern

## Implementation

```rust
impl<T> Bid<T> {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            _phantom: PhantomData,
        }
    }

    pub fn generate(prefix: &str) -> Self {
        let timestamp = Utc::now().timestamp_millis();
        let random = rand::random::<u16>();
        Self::new(format!("{}-{}-{}", prefix, timestamp, random))
    }
}
```

## Validation

Format validation ensures IDs meet organizational standards:

```rust
pub fn parse(s: &str) -> Option<Self> {
    if s.len() >= 3 && s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        Some(Self::new(s))
    } else {
        None
    }
}
```

---

# ADR 002: Hybrid RBAC/ABAC Authorization Model

## Status: Accepted

## Context

Pure RBAC becomes unwieldy with complex, context-dependent permissions. Pure ABAC is powerful but complex to manage. We need a balance that provides:
- Simple role-based rules for common cases
- Fine-grained attribute-based rules when needed
- Performance for high-throughput scenarios

## Decision

Implement a hybrid model with prioritized evaluation:

1. **RBAC first**: Fast path for role-based decisions
2. **ABAC fallback**: Context-aware evaluation for edge cases
3. **Deny-by-default**: Secure default position

```rust
pub struct InMemoryPolicyEngine {
    rbac: RbacEngine,
    abac: AbacEngine,
    evaluation_cache: DashMap<String, (Decision, DateTime<Utc>)>,
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
        // Check cache first
        let cache_key = self.make_cache_key(subject, &action, resource);
        if let Some(cached) = self.evaluation_cache.get(&cache_key) {
            let (decision, timestamp) = cached.value();
            if Utc::now().signed_duration_since(*timestamp).num_seconds() < self.cache_ttl {
                return Ok(*decision);
            }
        }

        // Fast path: RBAC evaluation
        let rbac_result = self.rbac.evaluate(subject, &action, resource);
        if rbac_result == Decision::Allow {
            return Ok(Decision::Allow);
        }

        // Fallback: ABAC with full context
        let abac_result = self.abac.evaluate(subject, action, resource, ctx).await?;

        // Cache result
        self.evaluation_cache.insert(cache_key, (abac_result, Utc::now()));

        Ok(abac_result)
    }
}
```

## Consequences

### Positive

1. **Performance**: RBAC cache hits are sub-millisecond
2. **Flexibility**: ABAC handles complex scenarios
3. **Migration path**: Can start with RBAC, add ABAC later
4. **Auditability**: Clear decision trail

### Negative

1. **Complexity**: Two systems to maintain
2. **Debugging**: Must understand which system made decision
3. **Policy conflicts**: Need resolution strategy

## Policy Priority Resolution

```rust
/// Priority-based policy evaluation
fn resolve_conflict(&self, rbac: Decision, abac: Decision) -> Decision {
    match (rbac, abac) {
        (Decision::Deny, _) => Decision::Deny,  // RBAC deny takes precedence
        (_, Decision::Deny) => Decision::Deny, // Explicit deny
        (Decision::Allow, Decision::Allow) => Decision::Allow,
        _ => Decision::Deny,  // Default deny
    }
}
```

---

# ADR 003: Async Security Aggregation with Concurrency Control

## Status: Accepted

## Context

Security data comes from multiple sources (Snyk, GitHub, custom scanners). Each source has different:
- Latency characteristics
- Rate limits
- Failure modes

We need to aggregate findings without:
- Sequential latency accumulation
- Unbounded resource consumption
- Cascading failures

## Decision

Implement concurrent aggregation with:
- Stream-based processing
- Bounded concurrency
- Circuit breaker pattern
- Graceful degradation

```rust
pub struct SecurityAggregator {
    sources: Vec<Box<dyn SecuritySource>>,
    concurrency_limit: usize,
    circuit_breakers: HashMap<String, CircuitBreaker>,
}

impl SecurityAggregator {
    pub async fn aggregate(&self) -> Result<SecurityReport, SecurityError> {
        let mut findings = Vec::new();

        // Process sources concurrently with backpressure
        let results = stream::iter(&self.sources)
            .map(|source| self.fetch_with_circuit_breaker(source))
            .buffer_unordered(self.concurrency_limit)
            .collect::<Vec<_>>()
            .await;

        // Aggregate successful results
        for result in results {
            match result {
                Ok(source_findings) => findings.extend(source_findings),
                Err(e) => tracing::warn!("Source failed, continuing: {}", e),
            }
        }

        self.build_report(findings)
    }

    async fn fetch_with_circuit_breaker(
        &self,
        source: &dyn SecuritySource,
    ) -> Result<Vec<Finding>, SecurityError> {
        let breaker = self.circuit_breakers.get(source.name())
            .ok_or_else(|| SecurityError::SourceError("Unknown source".into()))?;

        if !breaker.allow_request() {
            return Err(SecurityError::SourceError("Circuit open".into()));
        }

        match source.fetch_findings().await {
            Ok(findings) => {
                breaker.record_success();
                Ok(findings)
            }
            Err(e) => {
                breaker.record_failure();
                Err(e)
            }
        }
    }
}
```

## Consequences

### Positive

1. **Performance**: Parallel source fetching
2. **Resilience**: Circuit breakers prevent cascade failures
3. **Resource control**: Bounded concurrency limits
4. **Observability**: Per-source metrics

### Negative

1. **Complexity**: Async coordination overhead
2. **Ordering**: Non-deterministic source completion
3. **Debugging**: Concurrent execution harder to trace

## Circuit Breaker Implementation

```rust
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    consecutive_failures: AtomicU32,
    last_failure_time: Mutex<Option<Instant>>,
    state: AtomicState,
}

impl CircuitBreaker {
    pub fn allow_request(&self) -> bool {
        match self.state.load(Ordering::Relaxed) {
            State::Closed => true,
            State::Open => {
                if self.should_attempt_reset() {
                    self.state.store(State::HalfOpen, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            State::HalfOpen => true,
        }
    }
}
```

---

*ADRs AuthKit - Version 1.0*
