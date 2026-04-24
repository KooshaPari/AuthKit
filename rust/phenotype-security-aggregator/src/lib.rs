//! Phenotype Security Aggregator
//!
//! Aggregates security findings from multiple sources.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Security aggregation errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Aggregation failed: {0}")]
    AggregationFailed(String),
    #[error("Source error: {0}")]
    SourceError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Severity level for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Critical severity
    Critical,
    /// High severity
    High,
    /// Medium severity
    Medium,
    /// Low severity
    Low,
    /// Info-level severity
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    /// Get numeric value for sorting
    pub fn numeric_value(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.numeric_value().cmp(&other.numeric_value()))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.numeric_value().cmp(&other.numeric_value())
    }
}

/// Source of a security alert
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    /// Snyk security scanning
    Snyk,
    /// GitHub CodeQL
    CodeQL,
    /// Cargo audit for Rust
    CargoAudit,
    /// GitHub Dependabot
    Dependabot,
    /// Trivy container scanner
    Trivy,
    /// Custom source
    Custom(String),
}

impl AlertSource {
    /// Get short name for display
    pub fn short_name(&self) -> &str {
        match self {
            AlertSource::Snyk => "SNYK",
            AlertSource::CodeQL => "CODEQL",
            AlertSource::CargoAudit => "CARGO",
            AlertSource::Dependabot => "DEPND",
            AlertSource::Trivy => "TRIVY",
            AlertSource::Custom(s) => s.as_str(),
        }
    }

    /// Get full display name
    pub fn display_name(&self) -> String {
        match self {
            AlertSource::Custom(s) => format!("Custom ({})", s),
            _ => self.short_name().to_string(),
        }
    }
}

/// Individual security alert finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier
    pub id: String,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Source system
    pub source: AlertSource,
    /// File path (if applicable)
    pub file: Option<String>,
    /// Line number (if applicable)
    pub line: Option<u32>,
    /// When the alert was created
    pub created_at: DateTime<Utc>,
    /// CWE ID (if applicable)
    pub cwe_id: Option<String>,
    /// CVSS score (if applicable)
    pub cvss_score: Option<f32>,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        source: AlertSource,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            source,
            file: None,
            line: None,
            created_at: Utc::now(),
            cwe_id: None,
            cvss_score: None,
        }
    }

    /// Set the description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the file location
    pub fn with_file(mut self, file: impl Into<String>, line: u32) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self
    }

    /// Set the CWE ID
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }

    /// Set the CVSS score
    pub fn with_cvss(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }
}

/// Aggregated security report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityReport {
    /// When the report was generated
    pub generated_at: DateTime<Utc>,
    /// All findings
    pub findings: Vec<Finding>,
    /// Findings grouped by severity
    pub by_severity: HashMap<Severity, Vec<Finding>>,
    /// Findings grouped by source
    pub by_source: HashMap<String, Vec<Finding>>,
    /// Summary statistics
    pub summary: ReportSummary,
}

/// Report summary statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total number of findings
    pub total: usize,
    /// Critical count
    pub critical: usize,
    /// High count
    pub high: usize,
    /// Medium count
    pub medium: usize,
    /// Low count
    pub low: usize,
    /// Info count
    pub info: usize,
    /// Number of unique sources
    pub sources: usize,
}

/// Trait for security data sources
#[async_trait::async_trait]
pub trait SecuritySource: Send + Sync {
    /// Get source name
    fn name(&self) -> &str;

    /// Fetch findings from this source
    async fn fetch_findings(&self) -> Result<Vec<Finding>, SecurityError>;
}

/// Security aggregator that combines findings from multiple sources
#[derive(Default)]
pub struct SecurityAggregator {
    sources: Vec<Box<dyn SecuritySource>>,
}

impl std::fmt::Debug for SecurityAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityAggregator")
            .field("sources", &self.sources.len())
            .finish()
    }
}

impl SecurityAggregator {
    /// Create a new empty aggregator
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a security source
    pub fn add_source(&mut self, source: Box<dyn SecuritySource>) {
        info!("Adding security source: {}", source.name());
        self.sources.push(source);
    }

    /// Aggregate findings from all sources
    pub async fn aggregate(&self) -> Result<SecurityReport, SecurityError> {
        info!(
            "Aggregating security findings from {} sources",
            self.sources.len()
        );

        let mut all_findings = Vec::new();

        for source in &self.sources {
            debug!("Fetching from source: {}", source.name());

            match source.fetch_findings().await {
                Ok(findings) => {
                    info!("Got {} findings from {}", findings.len(), source.name());
                    all_findings.extend(findings);
                }
                Err(e) => {
                    warn!("Failed to fetch from {}: {}", source.name(), e);
                }
            }
        }

        Ok(self.build_report(all_findings))
    }

    /// Build a report from findings
    fn build_report(&self, findings: Vec<Finding>) -> SecurityReport {
        let generated_at = Utc::now();

        // Group by severity
        let mut by_severity: HashMap<Severity, Vec<Finding>> = HashMap::new();
        for finding in &findings {
            by_severity
                .entry(finding.severity)
                .or_default()
                .push(finding.clone());
        }

        // Group by source
        let mut by_source: HashMap<String, Vec<Finding>> = HashMap::new();
        for finding in &findings {
            let source_key = finding.source.short_name().to_string();
            by_source
                .entry(source_key)
                .or_default()
                .push(finding.clone());
        }

        // Build summary
        let summary = ReportSummary {
            total: findings.len(),
            critical: by_severity
                .get(&Severity::Critical)
                .map(|v| v.len())
                .unwrap_or(0),
            high: by_severity
                .get(&Severity::High)
                .map(|v| v.len())
                .unwrap_or(0),
            medium: by_severity
                .get(&Severity::Medium)
                .map(|v| v.len())
                .unwrap_or(0),
            low: by_severity
                .get(&Severity::Low)
                .map(|v| v.len())
                .unwrap_or(0),
            info: by_severity
                .get(&Severity::Info)
                .map(|v| v.len())
                .unwrap_or(0),
            sources: by_source.len(),
        };

        SecurityReport {
            generated_at,
            findings,
            by_severity,
            by_source,
            summary,
        }
    }

    /// Get critical findings only
    pub fn critical_findings(report: &SecurityReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect()
    }

    /// Get findings for a specific severity
    pub fn findings_by_severity(report: &SecurityReport, severity: Severity) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// Get risk score (0-100, higher is more risky)
    pub fn risk_score(report: &SecurityReport) -> u8 {
        if report.summary.total == 0 {
            return 0;
        }

        let critical_weight = report.summary.critical * 25;
        let high_weight = report.summary.high * 10;
        let medium_weight = report.summary.medium * 3;
        let low_weight = report.summary.low;

        let weighted_sum = critical_weight + high_weight + medium_weight + low_weight;
        // Cap at 100 to avoid overflow, but don't multiply (weights are already calibrated)
        weighted_sum.min(100) as u8
    }
}

/// Mock security source for testing
pub struct MockSecuritySource {
    name: String,
    findings: Vec<Finding>,
}

impl MockSecuritySource {
    /// Create a new mock source
    pub fn new(name: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            name: name.into(),
            findings,
        }
    }
}

#[async_trait::async_trait]
impl SecuritySource for MockSecuritySource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn fetch_findings(&self) -> Result<Vec<Finding>, SecurityError> {
        Ok(self.findings.clone())
    }
}

/// Example implementation for GitHub Security Advisory source
pub struct GitHubSecuritySource {
    repo: String,
    token: Option<String>,
}

impl GitHubSecuritySource {
    /// Create a new GitHub security source
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            token: std::env::var("GITHUB_TOKEN").ok(),
        }
    }

    /// Set authentication token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }
}

/// GitHub Security Alert from API
#[derive(Debug, Clone, Deserialize)]
struct GitHubAlert {
    number: u64,
    #[serde(rename = "security_advisory")]
    advisory: Option<GitHubAdvisory>,
    #[serde(rename = "security_vulnerability")]
    vulnerability: Option<GitHubVulnerability>,
    state: String,
    #[serde(rename = "dismissed_at")]
    dismissed_at: Option<DateTime<Utc>>,
}

/// GitHub Security Advisory
#[derive(Debug, Clone, Deserialize)]
struct GitHubAdvisory {
    summary: String,
    description: String,
    severity: String,
    cwe_ids: Option<Vec<String>>,
    #[serde(rename = "cvss")]
    cvss: Option<GitHubCvss>,
}

/// GitHub CVSS score
#[derive(Debug, Clone, Deserialize)]
struct GitHubCvss {
    score: f32,
}

/// GitHub Security Vulnerability
#[derive(Debug, Clone, Deserialize)]
struct GitHubVulnerability {
    package: GitHubPackage,
}

/// GitHub Package
#[derive(Debug, Clone, Deserialize)]
struct GitHubPackage {
    name: String,
    ecosystem: String,
}

impl GitHubSecuritySource {
    /// Fetch alerts from GitHub API
    async fn fetch_github_alerts(&self) -> Result<Vec<GitHubAlert>, SecurityError> {
        #[cfg(feature = "real-sources")]
        {
            use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};

            let token = self.token.as_ref().ok_or_else(|| {
                SecurityError::SourceError("GITHUB_TOKEN environment variable not set".to_string())
            })?;

            let url = format!(
                "https://api.github.com/repos/{}/dependabot/alerts",
                self.repo
            );

            let client = reqwest::Client::new();
            let response = client
                .get(&url)
                .header(AUTHORIZATION, format!("token {}", token))
                .header(ACCEPT, "application/vnd.github+json")
                .header(USER_AGENT, "phenotype-health")
                .send()
                .await
                .map_err(|e| SecurityError::SourceError(format!("HTTP error: {}", e)))?;

            if !response.status().is_success() {
                return Err(SecurityError::SourceError(format!(
                    "GitHub API returned status: {}",
                    response.status()
                )));
            }

            let alerts: Vec<GitHubAlert> = response
                .json()
                .await
                .map_err(|e| SecurityError::ParseError(format!("JSON parse error: {}", e)))?;

            Ok(alerts)
        }

        #[cfg(not(feature = "real-sources"))]
        {
            // Return empty when feature is disabled
            Ok(Vec::new())
        }
    }

    /// Convert GitHub alert to Finding
    fn convert_alert(&self, alert: GitHubAlert) -> Option<Finding> {
        // Skip dismissed alerts
        if alert.state == "dismissed" || alert.dismissed_at.is_some() {
            return None;
        }

        let advisory = alert.advisory.as_ref()?;
        let cwe_id = advisory
            .cwe_ids
            .as_ref()
            .and_then(|ids| ids.first().cloned());
        let cvss_score = advisory.cvss.as_ref().map(|c| c.score);

        let severity = match advisory.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "moderate" | "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };

        let vulnerability_info = alert.vulnerability.as_ref().map(|v| {
            let pkg = &v.package;
            format!("{}: {}", pkg.ecosystem, pkg.name)
        });

        let mut finding = Finding::new(
            format!("GHSA-{}", alert.number),
            advisory.summary.clone(),
            severity,
            AlertSource::Dependabot,
        )
        .with_description(advisory.description.clone())
        .with_cwe(cwe_id.unwrap_or_default());

        if let Some(score) = cvss_score {
            finding = finding.with_cvss(score);
        }

        if let Some(vuln_info) = vulnerability_info {
            finding.description = format!("{}\n\nPackage: {}", finding.description, vuln_info);
        }

        Some(finding)
    }
}

#[async_trait::async_trait]
impl SecuritySource for GitHubSecuritySource {
    fn name(&self) -> &str {
        "github-security"
    }

    async fn fetch_findings(&self) -> Result<Vec<Finding>, SecurityError> {
        info!("Fetching GitHub security data for: {}", self.repo);

        let alerts = self.fetch_github_alerts().await?;

        let findings: Vec<Finding> = alerts
            .into_iter()
            .filter_map(|alert| self.convert_alert(alert))
            .collect();

        info!("Converted {} GitHub alerts to findings", findings.len());

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_numeric_value() {
        assert_eq!(Severity::Critical.numeric_value(), 5);
        assert_eq!(Severity::Info.numeric_value(), 1);
    }

    #[test]
    fn test_finding_builder() {
        let finding = Finding::new(
            "CVE-2024-1234",
            "Test Vulnerability",
            Severity::High,
            AlertSource::Snyk,
        )
        .with_description("Test description")
        .with_file("src/main.rs", 42)
        .with_cwe("CWE-79")
        .with_cvss(7.5);

        assert_eq!(finding.id, "CVE-2024-1234");
        assert_eq!(finding.title, "Test Vulnerability");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.file, Some("src/main.rs".to_string()));
        assert_eq!(finding.line, Some(42));
        assert_eq!(finding.cwe_id, Some("CWE-79".to_string()));
        assert_eq!(finding.cvss_score, Some(7.5));
    }

    #[tokio::test]
    async fn test_security_aggregator() {
        let mut aggregator = SecurityAggregator::new();

        let mock_findings = vec![
            Finding::new("F1", "Finding 1", Severity::Critical, AlertSource::Snyk),
            Finding::new("F2", "Finding 2", Severity::High, AlertSource::CodeQL),
        ];

        let mock_source = MockSecuritySource::new("test-source", mock_findings);
        aggregator.add_source(Box::new(mock_source));

        let report = aggregator.aggregate().await.unwrap();
        assert_eq!(report.summary.total, 2);
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.summary.high, 1);
    }

    #[test]
    fn test_risk_score() {
        let report = SecurityReport {
            summary: ReportSummary {
                total: 10,
                critical: 1,
                high: 2,
                medium: 3,
                low: 4,
                info: 0,
                sources: 1,
            },
            ..Default::default()
        };

        let score = SecurityAggregator::risk_score(&report);
        assert!(score > 0);
        assert!(score <= 100);
    }

    #[test]
    fn test_alert_source_display() {
        let source = AlertSource::Custom("custom-tool".to_string());
        assert_eq!(source.display_name(), "Custom (custom-tool)");

        let snyk = AlertSource::Snyk;
        assert_eq!(snyk.short_name(), "SNYK");
    }

    #[test]
    fn test_severity_score_values() {
        // Score values based on numeric_value
        assert_eq!(Severity::Critical.numeric_value(), 5);
        assert_eq!(Severity::High.numeric_value(), 4);
        assert_eq!(Severity::Medium.numeric_value(), 3);
        assert_eq!(Severity::Low.numeric_value(), 2);
        assert_eq!(Severity::Info.numeric_value(), 1);
    }

    #[test]
    fn test_risk_score_empty_report() {
        let report = SecurityReport {
            summary: ReportSummary {
                total: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                sources: 0,
            },
            ..Default::default()
        };

        let score = SecurityAggregator::risk_score(&report);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_risk_score_decreases_with_critical_alerts() {
        // Empty report has risk score 0
        let empty_report = SecurityReport {
            summary: ReportSummary {
                total: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                sources: 0,
            },
            ..Default::default()
        };
        let empty_score = SecurityAggregator::risk_score(&empty_report);

        // Report with critical alerts has higher risk score
        let critical_report = SecurityReport {
            summary: ReportSummary {
                total: 1,
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                sources: 1,
            },
            ..Default::default()
        };
        let critical_score = SecurityAggregator::risk_score(&critical_report);

        // Critical alerts increase the risk score
        assert!(critical_score > empty_score);
        assert_eq!(critical_score, 25);
    }

    #[test]
    fn test_finding_new_creates_correct_fields() {
        let finding = Finding::new(
            "CVE-2024-1234",
            "Test Vulnerability",
            Severity::High,
            AlertSource::Snyk,
        );

        assert_eq!(finding.id, "CVE-2024-1234");
        assert_eq!(finding.title, "Test Vulnerability");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.source, AlertSource::Snyk);
        assert_eq!(finding.description, "");
        assert_eq!(finding.file, None);
        assert_eq!(finding.line, None);
        assert_eq!(finding.cwe_id, None);
        assert_eq!(finding.cvss_score, None);
    }
}
