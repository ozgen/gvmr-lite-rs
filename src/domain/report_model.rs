use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ReportEnvelope {
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

    pub owner: Option<Owner>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub writable: Option<String>,
    pub in_use: Option<String>,
    pub task: Option<EnvelopeTask>,
    pub report_format: Option<ReportFormatRef>,

    #[serde(rename = "report")]
    pub report: InnerReport,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Owner {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EnvelopeTask {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ReportFormatRef {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct InnerReport {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub gmp: Option<Gmp>,
    pub sort: Option<Sort>,
    pub filters: Option<Filters>,
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

    pub ports: Option<Ports>,
    pub results: Option<Results>,
    pub result_count: Option<ResultCount>,
    pub severity: Option<SeveritySummary>,

    #[serde(rename = "host", default)]
    pub hosts_detail: Vec<ReportHost>,

    pub tls_certificates: Option<EmptyNode>,
    pub errors: Option<CountNode>,
    pub report_format: Option<EmptyNode>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EmptyNode {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Gmp {
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Sort {
    pub field: Option<SortField>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct SortField {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub order: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Filters {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub term: Option<String>,

    #[serde(rename = "filter", default)]
    pub filter: Vec<String>,

    pub keywords: Option<FilterKeywords>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct FilterKeywords {
    #[serde(rename = "keyword", default)]
    pub keyword: Vec<FilterKeyword>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct FilterKeyword {
    pub column: Option<String>,
    pub relation: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct CountNode {
    pub count: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Task {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
    pub comment: Option<String>,
    pub target: Option<TaskTarget>,
    pub agent_group: Option<AgentGroup>,
    pub oci_image_target: Option<OciImageTarget>,
    pub progress: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct TaskTarget {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub trash: Option<String>,
    pub name: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AgentGroup {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub trash: Option<String>,
    pub name: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct OciImageTarget {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub trash: Option<String>,
    pub name: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Ports {
    #[serde(rename = "@start")]
    pub start: Option<String>,

    #[serde(rename = "@max")]
    pub max: Option<String>,

    pub count: Option<String>,

    #[serde(rename = "port", default)]
    pub port: Vec<PortEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct PortEntry {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub host: Option<String>,
    pub severity: Option<String>,
    pub threat: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Results {
    #[serde(rename = "@start")]
    pub start: Option<String>,

    #[serde(rename = "@max")]
    pub max: Option<String>,

    #[serde(rename = "result", default)]
    pub result: Vec<ReportResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ReportResult {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub name: Option<String>,
    pub owner: Option<Owner>,
    pub modification_time: Option<String>,
    pub comment: Option<String>,
    pub creation_time: Option<String>,

    pub host: Option<ResultHost>,
    pub port: Option<String>,

    pub nvt: Option<Nvt>,
    pub scan_nvt_version: Option<String>,
    pub threat: Option<String>,
    pub severity: Option<String>,
    pub qod: Option<Qod>,
    pub description: Option<String>,

    pub original_threat: Option<String>,
    pub original_severity: Option<String>,
    pub compliance: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ResultHost {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub asset: Option<AssetRef>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct AssetRef {
    #[serde(rename = "@asset_id")]
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Nvt {
    #[serde(rename = "@oid")]
    pub oid: Option<String>,

    pub r#type: Option<String>,
    pub name: Option<String>,
    pub family: Option<String>,
    pub cvss_base: Option<String>,
    pub severities: Option<NvtSeverities>,
    pub tags: Option<String>,
    pub solution: Option<Solution>,
    pub epss: Option<Epss>,
    pub refs: Option<Refs>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct NvtSeverities {
    #[serde(rename = "@score")]
    pub score: Option<String>,

    #[serde(rename = "severity", default)]
    pub severity: Vec<NvtSeverity>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct NvtSeverity {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,

    pub origin: Option<String>,
    pub date: Option<String>,
    pub score: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Solution {
    #[serde(rename = "@type")]
    pub r#type: Option<String>,

    #[serde(rename = "$text")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Epss {
    pub max_severity: Option<EpssEntry>,
    pub max_epss: Option<EpssEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EpssEntry {
    pub score: Option<String>,
    pub percentile: Option<String>,
    pub cve: Option<EpssCve>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EpssCve {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Refs {
    #[serde(rename = "ref", default)]
    pub reference: Vec<NvtRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct NvtRef {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    #[serde(rename = "@type")]
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct Qod {
    pub value: Option<String>,
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ResultCount {
    pub full: Option<String>,
    pub filtered: Option<String>,

    pub critical: Option<FullFiltered>,
    pub hole: Option<FullFiltered>,
    pub high: Option<FullFiltered>,
    pub info: Option<FullFiltered>,
    pub low: Option<FullFiltered>,
    pub log: Option<FullFiltered>,
    pub warning: Option<FullFiltered>,
    pub medium: Option<FullFiltered>,
    pub false_positive: Option<FullFiltered>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct FullFiltered {
    #[serde(rename = "@deprecated")]
    pub deprecated: Option<String>,

    pub full: Option<String>,
    pub filtered: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct SeveritySummary {
    pub full: Option<String>,
    pub filtered: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ReportHost {
    pub ip: Option<String>,
    pub asset: Option<AssetRef>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub port_count: Option<PageCountNode>,
    pub result_count: Option<HostResultCount>,

    #[serde(rename = "detail", default)]
    pub detail: Vec<HostDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct PageCountNode {
    pub page: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct HostResultCount {
    pub page: Option<String>,

    pub critical: Option<PageCountNode>,
    pub hole: Option<DeprecatedPageCountNode>,
    pub high: Option<PageCountNode>,
    pub warning: Option<DeprecatedPageCountNode>,
    pub medium: Option<PageCountNode>,
    pub info: Option<DeprecatedPageCountNode>,
    pub low: Option<PageCountNode>,
    pub log: Option<PageCountNode>,
    pub false_positive: Option<PageCountNode>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct DeprecatedPageCountNode {
    #[serde(rename = "@deprecated")]
    pub deprecated: Option<String>,

    pub page: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct HostDetail {
    pub name: Option<String>,
    pub value: Option<String>,
    pub source: Option<HostDetailSource>,
    pub extra: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct HostDetailSource {
    pub r#type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[cfg(test)]
#[path = "report_model_tests.rs"]
mod report_model_tests;
