use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RenderAuditRequest {
    pub format_id: String,

    pub report_json: AuditReportEnvelopeJson,

    #[serde(default)]
    pub params: Map<String, Value>,

    pub output_name: Option<String>,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl RenderAuditRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_id.trim().is_empty() {
            return Err("format_id must not be empty".to_string());
        }

        if self.timeout_seconds < 1 || self.timeout_seconds > 40001 {
            return Err("timeout_seconds must be between 1 and 40001".to_string());
        }

        Ok(())
    }

    pub fn report_json_value(&self) -> Value {
        serde_json::to_value(&self.report_json).unwrap_or(Value::Null)
    }

    pub fn inner_report_json_value(&self) -> Value {
        serde_json::to_value(&self.report_json.report).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RenderAuditXmlRequest {
    pub format_id: String,

    pub report_xml: String,

    #[serde(default)]
    pub params: Map<String, Value>,

    pub output_name: Option<String>,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl RenderAuditXmlRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_id.trim().is_empty() {
            return Err("format_id must not be empty".to_string());
        }

        if self.report_xml.trim().is_empty() {
            return Err("report_xml must not be empty".to_string());
        }

        if self.timeout_seconds < 1 || self.timeout_seconds > 40001 {
            return Err("timeout_seconds must be between 1 and 40001".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AuditReportEnvelopeJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub owner: Option<AuditOwnerJson>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub writable: Option<Value>,
    pub in_use: Option<Value>,
    pub task: Option<AuditTaskJson>,
    pub report_format: Option<AuditReportFormatJson>,

    pub report: AuditReportBodyJson,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditReportBodyJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub gmp: Option<AuditGmpJson>,
    pub sort: Option<Value>,
    pub filters: Option<AuditFiltersJson>,

    pub scan_run_status: Option<String>,

    pub hosts: Option<AuditCountNodeJson>,
    pub closed_cves: Option<AuditCountNodeJson>,
    pub cves: Option<AuditCountNodeJson>,
    pub vulns: Option<AuditCountNodeJson>,
    pub os: Option<AuditCountNodeJson>,
    pub apps: Option<AuditCountNodeJson>,
    pub ssl_certs: Option<AuditCountNodeJson>,

    pub task: Option<AuditTaskJson>,

    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub timezone: Option<String>,
    pub timezone_abbrev: Option<String>,

    pub ports: Option<AuditPortsJson>,
    pub results: Option<AuditResultsJson>,

    pub compliance_count: Option<AuditComplianceCountJson>,
    pub compliance: Option<AuditComplianceSummaryJson>,

    #[serde(default)]
    pub host: Vec<AuditHostJson>,

    pub tls_certificates: Option<AuditTlsCertificatesJson>,
    pub errors: Option<AuditErrorsJson>,
    pub report_format: Option<AuditReportFormatJson>,
    pub target: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditGmpJson {
    pub version: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditOwnerJson {
    pub name: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditCountNodeJson {
    pub count: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditTaskJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub id: Option<String>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub progress: Option<Value>,
    pub target: Option<AuditTaskTargetJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditTaskTargetJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub id: Option<String>,
    pub trash: Option<Value>,
    pub name: Option<String>,
    pub comment: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditFiltersJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub term: Option<String>,
    pub phrase: Option<String>,

    #[serde(default)]
    pub filter: Vec<String>,

    pub keywords: Option<AuditFilterKeywordsJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditFilterKeywordsJson {
    #[serde(default)]
    pub keyword: Vec<AuditFilterKeywordJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AuditFilterKeywordJson {
    pub column: String,

    #[serde(default = "default_filter_relation")]
    pub relation: String,

    pub value: Value,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditPortsJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub count: Option<Value>,

    #[serde(default)]
    pub port: Vec<AuditPortJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditPortJson {
    #[serde(rename = "#text")]
    pub text: Option<String>,

    pub host: Option<String>,
    pub threat: Option<String>,
    pub severity: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditResultsJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    #[serde(default)]
    pub result: Vec<AuditResultJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditResultJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub id: Option<String>,
    pub name: Option<String>,
    pub owner: Option<AuditOwnerJson>,
    pub modification_time: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,

    pub host: Option<AuditResultHostValueJson>,
    pub port: Option<String>,

    pub nvt: Option<AuditNvtJson>,
    pub scan_nvt_version: Option<String>,

    pub threat: Option<String>,
    pub severity: Option<Value>,
    pub qod: Option<AuditQodJson>,
    pub description: Option<String>,

    pub original_threat: Option<String>,
    pub original_severity: Option<Value>,
    pub compliance: Option<String>,

    pub detection: Option<Value>,
    pub notes: Option<Value>,
    pub overrides: Option<Value>,
    pub delta: Option<Value>,
    pub cve: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum AuditResultHostValueJson {
    String(String),
    Object(AuditResultHostJson),
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditResultHostJson {
    #[serde(rename = "#text")]
    pub text: Option<String>,

    pub asset: Option<AuditAssetRefJson>,
    pub hostname: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditAssetRefJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditNvtJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub oid: Option<String>,

    #[serde(rename = "type")]
    pub kind: Option<String>,

    pub name: Option<String>,
    pub family: Option<String>,
    pub cvss_base: Option<Value>,
    pub tags: Option<String>,
    pub solution: Option<Value>,
    pub refs: Option<Value>,
    pub epss: Option<Value>,
    pub severities: Option<Value>,
    pub cve: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditQodJson {
    pub value: Option<Value>,

    #[serde(rename = "type")]
    pub kind: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditComplianceCountJson {
    pub full: Option<Value>,
    pub filtered: Option<Value>,
    pub yes: Option<AuditFullFilteredJson>,
    pub no: Option<AuditFullFilteredJson>,
    pub incomplete: Option<AuditFullFilteredJson>,
    pub undefined: Option<AuditFullFilteredJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditFullFilteredJson {
    pub full: Option<Value>,
    pub filtered: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditComplianceSummaryJson {
    pub full: Option<Value>,
    pub filtered: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditHostJson {
    pub ip: Option<String>,
    pub asset: Option<AuditAssetRefJson>,
    pub start: Option<String>,
    pub end: Option<String>,

    pub port_count: Option<AuditPageCountJson>,

    pub compliance_count: Option<AuditHostComplianceCountJson>,
    pub host_compliance: Option<String>,

    #[serde(default)]
    pub detail: Vec<AuditHostDetailJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditHostComplianceCountJson {
    pub page: Option<Value>,
    pub yes: Option<AuditPageCountJson>,
    pub no: Option<AuditPageCountJson>,
    pub incomplete: Option<AuditPageCountJson>,
    pub undefined: Option<AuditPageCountJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditPageCountJson {
    pub page: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditHostDetailJson {
    pub name: Option<String>,
    pub value: Option<String>,
    pub source: Option<AuditHostDetailSourceJson>,
    pub extra: Option<String>,

    #[serde(flatten)]
    pub extra_fields: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditHostDetailSourceJson {
    #[serde(rename = "type")]
    pub kind: Option<String>,

    pub name: Option<String>,
    pub description: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditTlsCertificatesJson {
    #[serde(default)]
    pub tls_certificate: Vec<AuditTlsCertificateJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditTlsCertificateJson {
    pub name: Option<String>,
    pub certificate: Option<AuditCertificateJson>,
    pub sha256_fingerprint: Option<String>,
    pub md5_fingerprint: Option<String>,
    pub valid: Option<Value>,
    pub activation_time: Option<String>,
    pub expiration_time: Option<String>,
    pub subject_dn: Option<String>,
    pub issuer_dn: Option<String>,
    pub serial: Option<String>,
    pub host: Option<AuditTlsCertificateHostJson>,
    pub ports: Option<AuditTlsCertificatePortsJson>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditCertificateJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub format: Option<String>,

    #[serde(rename = "#text")]
    pub text: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditTlsCertificateHostJson {
    pub ip: Option<String>,
    pub hostname: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditTlsCertificatePortsJson {
    #[serde(default)]
    pub port: Vec<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditErrorsJson {
    pub count: Option<Value>,

    #[serde(default)]
    pub error: Vec<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AuditReportFormatJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub id: Option<String>,
    pub name: Option<String>,
    pub extension: Option<String>,
    pub content_type: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_timeout_seconds() -> u64 {
    300
}

fn default_filter_relation() -> String {
    "=".to_string()
}

#[cfg(test)]
#[path = "render_audit_tests.rs"]
mod render_audit_tests;
