use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum Scalar {
    String(String),
    Integer(i64),
    Float(f64),
    Bool(bool),
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct CountNode {
    pub count: Option<i64>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct FullFiltered {
    pub full: Option<i64>,
    pub filtered: Option<i64>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct PageCount {
    pub page: Option<i64>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct FilterKeyword {
    pub column: String,

    #[serde(default = "default_relation")]
    pub relation: String,

    pub value: Scalar,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_relation() -> String {
    "=".to_string()
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct FilterKeywords {
    #[serde(default)]
    pub keyword: Vec<FilterKeyword>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Filters {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    #[serde(default)]
    pub term: String,

    pub phrase: Option<String>,

    #[serde(default)]
    pub filter: Vec<String>,

    #[serde(default)]
    pub keywords: FilterKeywords,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct AssetRef {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Owner {
    pub name: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct HostDetailSource {
    pub r#type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct HostDetail {
    pub name: String,
    pub value: String,
    pub source: Option<HostDetailSource>,
    pub extra: Option<String>,

    #[serde(flatten)]
    pub extra_fields: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct ResultHost {
    #[serde(rename = "#text")]
    pub text: Option<String>,

    pub asset: Option<AssetRef>,
    pub hostname: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum HostValue {
    String(String),
    Object(ResultHost),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Qod {
    pub value: Option<Value>,
    pub r#type: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Detection {
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Nvt {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub r#type: Option<String>,
    pub name: Option<String>,
    pub family: Option<String>,
    pub cvss_base: Option<Value>,
    pub tags: Option<String>,
    pub solution: Option<Map<String, Value>>,
    pub refs: Option<Map<String, Value>>,
    pub epss: Option<Map<String, Value>>,
    pub severities: Option<Map<String, Value>>,
    pub cve: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ReportResult {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub name: Option<String>,
    pub owner: Option<Owner>,
    pub modification_time: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,

    pub host: HostValue,
    pub port: Option<String>,

    pub nvt: Option<Nvt>,
    pub scan_nvt_version: Option<String>,
    pub threat: Option<String>,
    pub severity: Option<Value>,
    pub qod: Option<Value>,
    pub description: Option<String>,

    pub original_threat: Option<String>,
    pub original_severity: Option<Value>,
    pub compliance: Option<String>,

    pub delta: Option<Map<String, Value>>,
    pub notes: Option<Map<String, Value>>,
    pub overrides: Option<Map<String, Value>>,
    pub detection: Option<Detection>,
    pub cve: Option<Map<String, Value>>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Results {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    #[serde(default)]
    pub result: Vec<ReportResult>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct ResultCount {
    pub full: Option<i64>,

    #[serde(default)]
    pub filtered: i64,

    pub total: Option<i64>,

    pub critical: Option<FullFiltered>,
    pub high: Option<FullFiltered>,
    pub medium: Option<FullFiltered>,
    pub low: Option<FullFiltered>,
    pub log: Option<FullFiltered>,
    pub false_positive: Option<FullFiltered>,
    pub warning: Option<FullFiltered>,
    pub info: Option<FullFiltered>,
    pub hole: Option<FullFiltered>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct HostResultCount {
    pub page: Option<i64>,
    pub critical: Option<PageCount>,
    pub hole: Option<PageCount>,
    pub high: Option<PageCount>,
    pub warning: Option<PageCount>,
    pub medium: Option<PageCount>,
    pub info: Option<PageCount>,
    pub low: Option<PageCount>,
    pub log: Option<PageCount>,
    pub false_positive: Option<PageCount>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct HostEntry {
    pub ip: String,
    pub asset: Option<AssetRef>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub port_count: Option<PageCount>,
    pub result_count: Option<HostResultCount>,

    #[serde(default)]
    pub detail: Vec<HostDetail>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct PortEntry {
    #[serde(rename = "#text")]
    pub text: Option<String>,

    pub host: String,
    pub threat: Option<String>,
    pub severity: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Ports {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub count: Option<i64>,

    #[serde(default)]
    pub port: Vec<PortEntry>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct TaskTarget {
    pub id: Option<String>,
    pub trash: Option<Value>,
    pub name: Option<String>,
    pub comment: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct Task {
    pub id: Option<String>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub progress: Option<Value>,
    pub target: Option<TaskTarget>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct SeveritySummary {
    pub full: Option<Value>,
    pub filtered: Option<Value>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Default)]
pub struct ReportJson {
    #[serde(rename = "@attrs")]
    pub attrs: Option<Map<String, Value>>,

    pub gmp: Option<Map<String, Value>>,
    pub sort: Option<Map<String, Value>>,

    #[serde(default)]
    pub filters: Filters,

    pub scan_run_status: Option<String>,

    pub hosts: Option<CountNode>,
    pub closed_cves: Option<CountNode>,
    pub vulns: Option<CountNode>,
    pub os: Option<CountNode>,
    pub apps: Option<CountNode>,
    pub ssl_certs: Option<CountNode>,

    pub task: Option<Task>,

    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub timezone: Option<String>,
    pub timezone_abbrev: Option<String>,

    #[serde(default)]
    pub ports: Ports,

    #[serde(default)]
    pub results: Results,

    #[serde(default)]
    pub result_count: ResultCount,

    pub severity: Option<SeveritySummary>,

    #[serde(default)]
    pub host: Vec<HostEntry>,

    pub tls_certificates: Option<Map<String, Value>>,
    pub errors: Option<Map<String, Value>>,
    pub report_format: Option<Map<String, Value>>,
    pub target: Option<Map<String, Value>>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RenderRequest {
    pub format_id: String,
    pub report_json: ReportJson,

    #[serde(default)]
    pub params: Map<String, Value>,

    pub output_name: Option<String>,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl RenderRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout_seconds < 1 || self.timeout_seconds > 1201 {
            return Err("timeout_seconds must be between 1 and 1201".to_string());
        }

        Ok(())
    }

    pub fn report_json_value(&self) -> Value {
        serde_json::to_value(&self.report_json).unwrap_or(Value::Null)
    }
}

fn default_timeout_seconds() -> u64 {
    300
}
