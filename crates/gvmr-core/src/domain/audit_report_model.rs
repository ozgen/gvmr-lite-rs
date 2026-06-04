use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(rename = "report")]
pub struct AuditReportEnvelope {
    #[serde(rename = "@content_type")]
    pub content_type: Option<String>,

    #[serde(rename = "@extension")]
    pub extension: Option<String>,

    #[serde(rename = "@id")]
    pub id: Option<String>,

    #[serde(rename = "@format_id")]
    pub format_id: Option<String>,

    #[serde(rename = "@config_id")]
    pub config_id: Option<String>,

    pub owner: Option<AuditOwner>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub writable: Option<String>,
    pub in_use: Option<String>,
    pub task: Option<AuditEnvelopeTask>,
    pub report_format: Option<AuditReportFormatRef>,

    #[serde(rename = "report")]
    pub report: AuditReport,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditReport {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub gmp: Option<AuditGmp>,
    pub sort: Option<AuditSort>,
    pub filters: Option<AuditFilters>,
    pub scan_run_status: Option<String>,
    pub hosts: Option<AuditCountNode>,
    pub closed_cves: Option<AuditCountNode>,
    pub cves: Option<AuditCountNode>,
    pub vulns: Option<AuditCountNode>,
    pub os: Option<AuditCountNode>,
    pub apps: Option<AuditCountNode>,
    pub ssl_certs: Option<AuditCountNode>,
    pub task: Option<AuditTask>,
    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub timezone: Option<String>,
    pub timezone_abbrev: Option<String>,
    pub ports: Option<AuditPorts>,
    pub results: Option<AuditResults>,
    pub compliance_count: Option<AuditComplianceCount>,
    pub compliance: Option<AuditComplianceSummary>,

    #[serde(rename = "host", default)]
    pub host: Vec<AuditHost>,

    pub tls_certificates: Option<AuditTlsCertificates>,
    pub errors: Option<AuditCountNode>,
    pub report_format: Option<AuditEmptyNode>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditOwner {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditEnvelopeTask {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditReportFormatRef {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditGmp {
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditSort {
    pub field: Option<AuditSortField>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditSortField {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub order: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditFilters {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub term: Option<String>,

    #[serde(rename = "filter", default)]
    pub filter: Vec<String>,

    pub keywords: Option<AuditFilterKeywords>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditFilterKeywords {
    #[serde(rename = "keyword", default)]
    pub keyword: Vec<AuditFilterKeyword>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditFilterKeyword {
    pub column: Option<String>,
    pub relation: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditCountNode {
    pub count: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditTask {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
    pub comment: Option<String>,
    pub target: Option<AuditTaskTarget>,
    pub progress: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditTaskTarget {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub trash: Option<String>,
    pub name: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditPorts {
    #[serde(rename = "@start")]
    pub start: Option<String>,

    #[serde(rename = "@max")]
    pub max: Option<String>,

    pub count: Option<String>,

    #[serde(rename = "port", default)]
    pub port: Vec<AuditPort>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditPort {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub host: Option<String>,
    pub severity: Option<String>,
    pub threat: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditResults {
    #[serde(rename = "@start")]
    pub start: Option<String>,

    #[serde(rename = "@max")]
    pub max: Option<String>,

    #[serde(rename = "result", default)]
    pub result: Vec<AuditResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditResult {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
    pub owner: Option<AuditOwner>,
    pub modification_time: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,
    pub detection: Option<AuditDetection>,
    pub host: Option<AuditResultHost>,
    pub port: Option<String>,
    pub nvt: Option<AuditNvt>,
    pub scan_nvt_version: Option<String>,
    pub threat: Option<String>,
    pub severity: Option<String>,
    pub qod: Option<AuditQod>,
    pub description: Option<String>,
    pub original_threat: Option<String>,
    pub original_severity: Option<String>,
    pub compliance: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditDetection {
    pub result: Option<AuditDetectionResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditDetectionResult {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub details: Option<AuditDetectionDetails>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditDetectionDetails {
    #[serde(rename = "detail", default)]
    pub detail: Vec<AuditDetectionDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditDetectionDetail {
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditResultHost {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub asset: Option<AuditAsset>,
    pub hostname: Option<String>,
}

impl AuditResultHost {
    pub fn address(&self) -> Option<&str> {
        self.text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn hostname(&self) -> Option<&str> {
        self.hostname
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn display_name(&self) -> Option<&str> {
        self.hostname()
            .and_then(|hostname| hostname.rsplit('/').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| self.address())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditAsset {
    #[serde(rename = "@asset_id")]
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditNvt {
    #[serde(rename = "@oid")]
    pub oid: Option<String>,

    #[serde(rename = "type")]
    pub kind: Option<String>,

    pub name: Option<String>,
    pub family: Option<String>,
    pub cvss_base: Option<String>,
    pub severities: Option<AuditNvtSeverities>,
    pub tags: Option<String>,
    pub solution: Option<AuditSolution>,
    pub refs: Option<AuditRefs>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditNvtSeverities {
    #[serde(rename = "@score")]
    pub score: Option<String>,

    #[serde(rename = "severity", default)]
    pub severity: Vec<AuditNvtSeverity>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditNvtSeverity {
    #[serde(rename = "@type")]
    pub kind: Option<String>,

    pub origin: Option<String>,
    pub date: Option<String>,
    pub score: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditSolution {
    #[serde(rename = "@type")]
    pub kind: Option<String>,

    #[serde(rename = "$text")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditRefs {
    #[serde(rename = "ref", default)]
    pub reference: Vec<AuditRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditRef {
    #[serde(rename = "@type")]
    pub kind: Option<String>,

    #[serde(rename = "@id")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditQod {
    pub value: Option<String>,

    #[serde(rename = "type")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditComplianceCount {
    #[serde(rename = "$text")]
    pub total: Option<String>,

    pub full: Option<String>,
    pub filtered: Option<String>,
    pub yes: Option<AuditFullFilteredCount>,
    pub no: Option<AuditFullFilteredCount>,
    pub incomplete: Option<AuditFullFilteredCount>,
    pub undefined: Option<AuditFullFilteredCount>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditFullFilteredCount {
    pub full: Option<String>,
    pub filtered: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditComplianceSummary {
    pub full: Option<String>,
    pub filtered: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditHost {
    pub ip: Option<String>,
    pub asset: Option<AuditAsset>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub port_count: Option<AuditPageCount>,
    pub compliance_count: Option<AuditHostComplianceCount>,
    pub host_compliance: Option<String>,

    #[serde(rename = "detail", default)]
    pub detail: Vec<AuditHostDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditHostComplianceCount {
    pub page: Option<String>,
    pub yes: Option<AuditPageCount>,
    pub no: Option<AuditPageCount>,
    pub incomplete: Option<AuditPageCount>,
    pub undefined: Option<AuditPageCount>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditPageCount {
    pub page: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditHostDetail {
    pub name: Option<String>,
    pub value: Option<String>,
    pub source: Option<AuditHostDetailSource>,
    pub extra: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditHostDetailSource {
    #[serde(rename = "type")]
    pub kind: Option<String>,

    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditTlsCertificates {
    #[serde(rename = "tls_certificate", default)]
    pub tls_certificate: Vec<AuditTlsCertificate>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditTlsCertificate {
    pub name: Option<String>,
    pub certificate: Option<AuditCertificate>,
    pub sha256_fingerprint: Option<String>,
    pub md5_fingerprint: Option<String>,
    pub valid: Option<String>,
    pub activation_time: Option<String>,
    pub expiration_time: Option<String>,
    pub subject_dn: Option<String>,
    pub issuer_dn: Option<String>,
    pub serial: Option<String>,
    pub host: Option<AuditTlsCertificateHost>,
    pub ports: Option<AuditTlsCertificatePorts>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditCertificate {
    #[serde(rename = "@format")]
    pub format: Option<String>,

    #[serde(rename = "$text")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditTlsCertificateHost {
    pub ip: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditTlsCertificatePorts {
    #[serde(rename = "port", default)]
    pub port: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AuditEmptyNode {}

#[cfg(test)]
#[path = "audit_report_model_tests.rs"]
mod audit_report_model_tests;
