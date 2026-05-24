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

impl InnerReport {
    pub fn is_container_image_report(&self) -> bool {
        self.task
            .as_ref()
            .and_then(|task| task.oci_image_target.as_ref())
            .is_some()
    }

    pub fn is_agent_report(&self) -> bool {
        self.task
            .as_ref()
            .and_then(|task| task.agent_group.as_ref())
            .is_some()
    }

    pub fn auth_rows(&self) -> Vec<AuthRow> {
        let mut rows = Vec::new();

        for host in &self.hosts_detail {
            let target = if self.is_agent_report() {
                host.agent_id()
                    .or_else(|| host.hostname())
                    .or_else(|| host.address())
                    .unwrap_or("")
                    .to_string()
            } else {
                host.display_name().unwrap_or_default()
            };

            if target.trim().is_empty() {
                continue;
            }

            for detail in &host.detail {
                let Some(name) = detail.name.as_deref().map(str::trim) else {
                    continue;
                };

                let Some(value) = detail
                    .value
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };

                let Some((protocol, result)) = auth_detail_kind(name) else {
                    continue;
                };

                rows.push(AuthRow {
                    target: target.clone(),
                    protocol,
                    result,
                    value: value.to_string(),
                });
            }
        }

        rows
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRow {
    pub target: String,
    pub protocol: &'static str,
    pub result: &'static str,
    pub value: String,
}

fn auth_detail_kind(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "Auth-SSH-Success" => Some(("SSH", "Success")),
        "Auth-SSH-Failure" => Some(("SSH", "Failure")),

        "Auth-SMB-Success" => Some(("SMB", "Success")),
        "Auth-SMB-Failure" => Some(("SMB", "Failure")),

        "Auth-ESXi-Success" => Some(("ESXi", "Success")),
        "Auth-ESXi-Failure" => Some(("ESXi", "Failure")),

        "Auth-SNMP-Success" => Some(("SNMP", "Success")),
        "Auth-SNMP-Failure" => Some(("SNMP", "Failure")),

        _ => None,
    }
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
pub struct OciImage {
    pub name: Option<String>,
    pub digest: Option<String>,
    pub registry: Option<String>,
    pub path: Option<String>,
    pub short_name: Option<String>,
}

impl OciImage {
    pub fn display_name(&self) -> Option<&str> {
        self.short_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                self.name
                    .as_deref()
                    .and_then(|name| name.rsplit('/').next())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
    }

    pub fn full_name(&self) -> Option<&str> {
        self.name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn digest(&self) -> Option<&str> {
        self.digest
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
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

    #[serde(default)]
    pub oci_image: Option<OciImage>,

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

impl ReportResult {
    pub fn target_address(&self) -> Option<&str> {
        self.host.as_ref().and_then(ResultHost::address)
    }

    pub fn target_display_name(&self) -> Option<&str> {
        self.oci_image
            .as_ref()
            .and_then(OciImage::display_name)
            .or_else(|| self.host.as_ref().and_then(ResultHost::display_name))
    }

    pub fn image_full_name(&self) -> Option<&str> {
        self.oci_image.as_ref().and_then(OciImage::full_name)
    }

    pub fn image_digest(&self) -> Option<&str> {
        self.oci_image
            .as_ref()
            .and_then(OciImage::digest)
            .or_else(|| self.target_address())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ResultHost {
    #[serde(rename = "$text")]
    pub text: Option<String>,

    pub asset: Option<AssetRef>,
    pub hostname: Option<String>,
}

impl ResultHost {
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

impl ReportHost {
    pub fn address(&self) -> Option<&str> {
        self.ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn detail_value(&self, name: &str) -> Option<&str> {
        self.detail
            .iter()
            .find(|detail| {
                detail
                    .name
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|value| value.eq_ignore_ascii_case(name))
            })
            .and_then(|detail| detail.value.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn hostname(&self) -> Option<&str> {
        self.detail_value("hostname")
    }

    pub fn agent_id(&self) -> Option<&str> {
        self.detail_value("agentID")
    }

    pub fn architecture(&self) -> Option<&str> {
        self.detail_value("ARCHITECTURE")
    }

    pub fn display_name(&self) -> Option<String> {
        let address = self.address()?;

        match self.hostname() {
            Some(hostname) => Some(format!("{address} - {hostname}")),
            None => Some(address.to_string()),
        }
    }
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
