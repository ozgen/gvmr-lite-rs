use serde_json::{Map, Value};

use crate::api::dto::render as dto;

use gvmr_core::domain::report_model::{self as domain, OciImage};

pub fn report_json_to_envelope(report_json: &dto::ReportJson) -> domain::ReportEnvelope {
    domain::ReportEnvelope {
        content_type: None,
        extension: None,
        id: attr_string(report_json.attrs.as_ref(), "id"),
        format_id: attr_string(report_json.attrs.as_ref(), "format_id"),
        config_id: attr_string(report_json.attrs.as_ref(), "config_id"),
        owner: None,
        name: Some("Scan Report".to_string()),
        comment: None,
        creation_time: None,
        modification_time: None,
        writable: None,
        in_use: None,
        task: None,
        report_format: None,
        report: report_json_to_inner_report(report_json),
    }
}

fn report_json_to_inner_report(report_json: &dto::ReportJson) -> domain::InnerReport {
    domain::InnerReport {
        id: attr_string(report_json.attrs.as_ref(), "id"),
        gmp: report_json.gmp.as_ref().map(gmp_from_map),
        sort: None,
        filters: Some(filters_from_dto(&report_json.filters)),
        scan_run_status: report_json.scan_run_status.clone(),

        hosts: report_json.hosts.as_ref().map(count_node_from_dto),
        closed_cves: report_json.closed_cves.as_ref().map(count_node_from_dto),
        vulns: report_json.vulns.as_ref().map(count_node_from_dto),
        os: report_json.os.as_ref().map(count_node_from_dto),
        apps: report_json.apps.as_ref().map(count_node_from_dto),
        ssl_certs: report_json.ssl_certs.as_ref().map(count_node_from_dto),

        task: report_json.task.as_ref().map(task_from_dto),

        timestamp: report_json.timestamp.clone(),
        scan_start: report_json.scan_start.clone(),
        scan_end: report_json.scan_end.clone(),
        timezone: report_json.timezone.clone(),
        timezone_abbrev: report_json.timezone_abbrev.clone(),

        ports: Some(ports_from_dto(&report_json.ports)),
        results: Some(results_from_dto(&report_json.results)),
        result_count: Some(result_count_from_dto(&report_json.result_count)),
        severity: report_json.severity.as_ref().map(severity_from_dto),

        hosts_detail: report_json.host.iter().map(report_host_from_dto).collect(),

        tls_certificates: None,
        errors: None,
        report_format: None,
    }
}

fn gmp_from_map(map: &Map<String, Value>) -> domain::Gmp {
    domain::Gmp {
        version: map_string(map, "version"),
    }
}

fn filters_from_dto(filters: &dto::Filters) -> domain::Filters {
    domain::Filters {
        id: attr_string(filters.attrs.as_ref(), "id"),
        term: Some(filters.term.clone()).filter(|value| !value.trim().is_empty()),
        filter: filters.filter.clone(),
        keywords: Some(domain::FilterKeywords {
            keyword: filters
                .keywords
                .keyword
                .iter()
                .map(|keyword| domain::FilterKeyword {
                    column: Some(keyword.column.clone()),
                    relation: Some(keyword.relation.clone()),
                    value: Some(scalar_to_string(&keyword.value)),
                })
                .collect(),
        }),
    }
}

fn count_node_from_dto(node: &dto::CountNode) -> domain::CountNode {
    domain::CountNode {
        count: node.count.map(|value| value.to_string()),
    }
}

fn task_from_dto(task: &dto::Task) -> domain::Task {
    domain::Task {
        id: task.id.clone(),
        name: task.name.clone(),
        comment: task.comment.clone(),
        target: task.target.as_ref().map(task_target_from_dto),
        agent_group: None,
        oci_image_target: None,
        progress: value_to_string(task.progress.as_ref()),
    }
}

fn task_target_from_dto(target: &dto::TaskTarget) -> domain::TaskTarget {
    domain::TaskTarget {
        id: target.id.clone(),
        trash: value_to_string(target.trash.as_ref()),
        name: target.name.clone(),
        comment: target.comment.clone(),
    }
}

fn ports_from_dto(ports: &dto::Ports) -> domain::Ports {
    domain::Ports {
        start: attr_string(ports.attrs.as_ref(), "start"),
        max: attr_string(ports.attrs.as_ref(), "max"),
        count: ports.count.map(|value| value.to_string()),
        port: ports.port.iter().map(port_entry_from_dto).collect(),
    }
}

fn port_entry_from_dto(port: &dto::PortEntry) -> domain::PortEntry {
    domain::PortEntry {
        text: port.text.clone(),
        host: Some(port.host.clone()),
        severity: value_to_string(port.severity.as_ref()),
        threat: port.threat.clone(),
    }
}

fn results_from_dto(results: &dto::Results) -> domain::Results {
    let result = results
        .result
        .iter()
        .filter(|result| should_keep_result(result))
        .map(report_result_from_dto)
        .collect();

    domain::Results {
        start: attr_string(results.attrs.as_ref(), "start"),
        max: attr_string(results.attrs.as_ref(), "max"),
        result,
    }
}

fn should_keep_result(result: &dto::ReportResult) -> bool {
    let threat = result.threat.as_deref().unwrap_or("").trim();

    if threat.is_empty() {
        return false;
    }

    if threat.eq_ignore_ascii_case("info")
        || threat.eq_ignore_ascii_case("log")
        || threat.eq_ignore_ascii_case("debug")
        || threat.eq_ignore_ascii_case("false positive")
    {
        return false;
    }

    true
}

fn report_result_from_dto(result: &dto::ReportResult) -> domain::ReportResult {
    domain::ReportResult {
        id: attr_string(result.attrs.as_ref(), "id"),
        name: result.name.clone(),
        owner: result.owner.as_ref().map(owner_from_dto),
        modification_time: result.modification_time.clone(),
        comment: result.comment.clone(),
        creation_time: result.creation_time.clone(),

        host: Some(result_host_from_dto(&result.host)),
        port: result.port.clone(),

        nvt: result.nvt.as_ref().map(nvt_from_dto),
        scan_nvt_version: result.scan_nvt_version.clone(),
        threat: result.threat.clone(),
        severity: value_to_string(result.severity.as_ref()),
        qod: result.qod.as_ref().map(qod_from_value),
        description: result.description.clone(),
        oci_image: Some(OciImage::default()), // Not present in the DTO, so we set it to an empty value

        original_threat: result.original_threat.clone(),
        original_severity: value_to_string(result.original_severity.as_ref()),
        compliance: result.compliance.clone(),
    }
}

fn owner_from_dto(owner: &dto::Owner) -> domain::Owner {
    domain::Owner {
        name: owner.name.clone(),
    }
}

fn result_host_from_dto(host: &dto::HostValue) -> domain::ResultHost {
    match host {
        dto::HostValue::String(value) => domain::ResultHost {
            text: Some(value.clone()),
            asset: None,
            hostname: None,
        },
        dto::HostValue::Object(host) => domain::ResultHost {
            text: host.text.clone(),
            asset: host.asset.as_ref().map(asset_ref_from_dto),
            hostname: host.hostname.clone(),
        },
    }
}

fn asset_ref_from_dto(asset: &dto::AssetRef) -> domain::AssetRef {
    domain::AssetRef {
        asset_id: attr_string(asset.attrs.as_ref(), "asset_id"),
    }
}

fn nvt_from_dto(nvt: &dto::Nvt) -> domain::Nvt {
    domain::Nvt {
        oid: attr_string(nvt.attrs.as_ref(), "oid"),
        r#type: nvt.r#type.clone(),
        name: nvt.name.clone(),
        family: nvt.family.clone(),
        cvss_base: value_to_string(nvt.cvss_base.as_ref()),
        severities: None,
        tags: nvt.tags.clone(),
        solution: nvt.solution.as_ref().map(solution_from_map),
        epss: None,
        refs: nvt.refs.as_ref().map(refs_from_map),
    }
}

fn solution_from_map(map: &Map<String, Value>) -> domain::Solution {
    domain::Solution {
        r#type: attr_string(Some(map), "type").or_else(|| map_string(map, "type")),
        text: map_string(map, "#text")
            .or_else(|| map_string(map, "$text"))
            .or_else(|| map_string(map, "text")),
    }
}

fn refs_from_map(map: &Map<String, Value>) -> domain::Refs {
    let mut reference = Vec::new();

    if let Some(value) = map.get("ref") {
        collect_refs(value, &mut reference);
    } else {
        collect_refs(&Value::Object(map.clone()), &mut reference);
    }

    domain::Refs { reference }
}

fn collect_refs(value: &Value, out: &mut Vec<domain::NvtRef>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_refs(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(reference) = ref_from_map(map) {
                out.push(reference);
            }
        }
        Value::String(value) if !value.trim().is_empty() => {
            out.push(domain::NvtRef {
                id: Some(value.clone()),
                r#type: None,
            });
        }
        _ => {}
    }
}

fn ref_from_map(map: &Map<String, Value>) -> Option<domain::NvtRef> {
    let attrs = map.get("@attrs").and_then(Value::as_object);

    let id = attr_string(attrs, "id")
        .or_else(|| attr_string(Some(map), "id"))
        .or_else(|| map_string(map, "id"));

    let r#type = attr_string(attrs, "type")
        .or_else(|| attr_string(Some(map), "type"))
        .or_else(|| map_string(map, "type"));

    if id.as_deref().unwrap_or("").trim().is_empty() {
        return None;
    }

    Some(domain::NvtRef { id, r#type })
}

fn qod_from_value(value: &Value) -> domain::Qod {
    match value {
        Value::Object(map) => domain::Qod {
            value: map.get("value").and_then(value_to_string_from_value),
            r#type: map
                .get("type")
                .or_else(|| map.get("@type"))
                .and_then(value_to_string_from_value),
        },
        other => domain::Qod {
            value: value_to_string_from_value(other),
            r#type: None,
        },
    }
}

fn result_count_from_dto(count: &dto::ResultCount) -> domain::ResultCount {
    domain::ResultCount {
        full: count.full.map(|value| value.to_string()),
        filtered: Some(count.filtered.to_string()),

        critical: count.critical.as_ref().map(full_filtered_from_dto),
        hole: count.hole.as_ref().map(full_filtered_from_dto),
        high: count.high.as_ref().map(full_filtered_from_dto),
        info: count.info.as_ref().map(full_filtered_from_dto),
        low: count.low.as_ref().map(full_filtered_from_dto),
        log: count.log.as_ref().map(full_filtered_from_dto),
        warning: count.warning.as_ref().map(full_filtered_from_dto),
        medium: count.medium.as_ref().map(full_filtered_from_dto),
        false_positive: count.false_positive.as_ref().map(full_filtered_from_dto),
    }
}

fn full_filtered_from_dto(value: &dto::FullFiltered) -> domain::FullFiltered {
    domain::FullFiltered {
        deprecated: None,
        full: value.full.map(|value| value.to_string()),
        filtered: value.filtered.map(|value| value.to_string()),
    }
}

fn severity_from_dto(severity: &dto::SeveritySummary) -> domain::SeveritySummary {
    domain::SeveritySummary {
        full: value_to_string(severity.full.as_ref()),
        filtered: value_to_string(severity.filtered.as_ref()),
    }
}

fn report_host_from_dto(host: &dto::HostEntry) -> domain::ReportHost {
    domain::ReportHost {
        ip: host.ip.clone(),
        asset: host.asset.as_ref().map(asset_ref_from_dto),
        start: host.start.clone(),
        end: host.end.clone(),
        port_count: host.port_count.as_ref().map(page_count_from_dto),
        result_count: host.result_count.as_ref().map(host_result_count_from_dto),
        detail: host.detail.iter().map(host_detail_from_dto).collect(),
    }
}

fn host_detail_from_dto(detail: &dto::HostDetail) -> domain::HostDetail {
    domain::HostDetail {
        name: Some(detail.name.clone()),
        value: Some(detail.value.clone()),
        source: detail.source.as_ref().map(host_detail_source_from_dto),
        extra: detail.extra.clone(),
    }
}

fn host_detail_source_from_dto(source: &dto::HostDetailSource) -> domain::HostDetailSource {
    domain::HostDetailSource {
        r#type: source.r#type.clone(),
        name: source.name.clone(),
        description: source.description.clone(),
    }
}

fn host_result_count_from_dto(count: &dto::HostResultCount) -> domain::HostResultCount {
    domain::HostResultCount {
        page: count.page.map(|value| value.to_string()),
        critical: count.critical.as_ref().map(page_count_from_dto),
        hole: count.hole.as_ref().map(deprecated_page_count_from_dto),
        high: count.high.as_ref().map(page_count_from_dto),
        warning: count.warning.as_ref().map(deprecated_page_count_from_dto),
        medium: count.medium.as_ref().map(page_count_from_dto),
        info: count.info.as_ref().map(deprecated_page_count_from_dto),
        low: count.low.as_ref().map(page_count_from_dto),
        log: count.log.as_ref().map(page_count_from_dto),
        false_positive: count.false_positive.as_ref().map(page_count_from_dto),
    }
}

fn page_count_from_dto(count: &dto::PageCount) -> domain::PageCountNode {
    domain::PageCountNode {
        page: count.page.map(|value| value.to_string()),
    }
}

fn deprecated_page_count_from_dto(count: &dto::PageCount) -> domain::DeprecatedPageCountNode {
    domain::DeprecatedPageCountNode {
        deprecated: None,
        page: count.page.map(|value| value.to_string()),
    }
}

fn attr_string(attrs: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    let attrs = attrs?;

    let direct = attrs.get(key).and_then(value_to_string_from_value);
    if direct.is_some() {
        return direct;
    }

    let prefixed_key = format!("@{key}");
    attrs
        .get(&prefixed_key)
        .and_then(value_to_string_from_value)
}

fn map_string(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(value_to_string_from_value)
}

fn value_to_string(value: Option<&Value>) -> Option<String> {
    value.and_then(value_to_string_from_value)
}

fn value_to_string_from_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) => Some(value.to_string()),
    }
}

fn scalar_to_string(value: &dto::Scalar) -> String {
    match value {
        dto::Scalar::String(value) => value.clone(),
        dto::Scalar::Integer(value) => value.to_string(),
        dto::Scalar::Float(value) => value.to_string(),
        dto::Scalar::Bool(value) => value.to_string(),
    }
}

#[cfg(test)]
#[path = "report_json_converter_tests.rs"]
mod report_json_converter_tests;
