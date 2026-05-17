use std::collections::BTreeMap;

use crate::domain::report_model::{ReportEnvelope, ReportResult};

pub fn report_timestamp(report: &ReportEnvelope) -> String {
    report
        .report
        .timestamp
        .as_deref()
        .or(report.creation_time.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
        .to_string()
}

pub fn build_summary_text(report: &ReportEnvelope) -> String {
    let timezone = report.report.timezone.as_deref().unwrap_or("unknown");
    let timezone_abbrev = report.report.timezone_abbrev.as_deref().unwrap_or("");
    let task = report_task_name(report);
    let scan_start = report.report.scan_start.as_deref().unwrap_or("unknown");
    let scan_end = report.report.scan_end.as_deref().unwrap_or("unknown");

    format!(
        "This document reports on the results of an automatic security scan. \
All dates are displayed using the timezone \"{timezone}\", which is abbreviated \"{timezone_abbrev}\". \
The task was \"{task}\". The scan started at {scan_start} and ended at {scan_end}. \
The report first summarises the results found. Then, for each host, the report describes every issue found. \
Please consider the advice given in each description, in order to rectify the issue."
    )
}

pub fn report_task_name(report: &ReportEnvelope) -> &str {
    report
        .report
        .task
        .as_ref()
        .and_then(|task| task.name.as_deref())
        .or_else(|| report.task.as_ref().and_then(|task| task.name.as_deref()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Unknown task")
}

pub fn report_results(report: &ReportEnvelope) -> &[ReportResult] {
    report
        .report
        .results
        .as_ref()
        .map(|results| results.result.as_slice())
        .unwrap_or_default()
}

pub fn results_by_host(report: &ReportEnvelope) -> BTreeMap<String, Vec<&ReportResult>> {
    let mut grouped = BTreeMap::new();

    for result in report_results(report) {
        grouped
            .entry(finding_host(result).to_string())
            .or_insert_with(Vec::new)
            .push(result);
    }

    grouped
}

pub fn build_filter_notes(report: &ReportEnvelope) -> String {
    let filtered = report
        .report
        .result_count
        .as_ref()
        .and_then(|count| count.filtered.as_deref())
        .unwrap_or("");

    let full = report
        .report
        .result_count
        .as_ref()
        .and_then(|count| count.full.as_deref())
        .unwrap_or("");

    format!(
        "Only results matching the selected report filters are shown.\n\n\
This report contains {filtered} results selected by the filtering described above. \
Before filtering there were {full} results."
    )
}

pub fn finding_host(result: &ReportResult) -> &str {
    result
        .host
        .as_ref()
        .and_then(|host| host.text.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
}

pub fn finding_port(result: &ReportResult) -> &str {
    result
        .port
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("general/tcp")
}

pub fn finding_threat(result: &ReportResult) -> &str {
    result
        .threat
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Log")
}

pub fn finding_severity(result: &ReportResult) -> &str {
    result
        .severity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
}

pub fn finding_qod(result: &ReportResult) -> &str {
    result
        .qod
        .as_ref()
        .and_then(|qod| qod.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
}

pub fn finding_name(result: &ReportResult) -> &str {
    result
        .nvt
        .as_ref()
        .and_then(|nvt| nvt.name.as_deref())
        .or(result.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Finding")
}

pub fn finding_solution(result: &ReportResult) -> Option<String> {
    let solution = result.nvt.as_ref()?.solution.as_ref()?;

    let solution_type = solution.r#type.as_deref().unwrap_or("").trim();
    let text = solution.text.as_deref().unwrap_or("").trim();

    match (solution_type.is_empty(), text.is_empty()) {
        (true, true) => None,
        (true, false) => Some(text.to_string()),
        (false, true) => Some(format!("Solution type: {solution_type}")),
        (false, false) => Some(format!("Solution type: {solution_type}\n{text}")),
    }
}

pub fn finding_references(result: &ReportResult) -> Vec<String> {
    result
        .nvt
        .as_ref()
        .and_then(|nvt| nvt.refs.as_ref())
        .map(|refs| {
            refs.reference
                .iter()
                .filter_map(|reference| {
                    let id = reference.id.as_deref()?.trim();

                    if id.is_empty() {
                        return None;
                    }

                    match reference
                        .r#type
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        Some(kind) => Some(format!("{kind}: {id}")),
                        None => Some(id.to_string()),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn finding_detection_method(result: &ReportResult) -> Option<String> {
    let nvt = result.nvt.as_ref()?;

    let mut parts = Vec::new();

    if let Some(method) = finding_nvt_tag(result, "vuldetect") {
        parts.push(method);
    }

    if let Some(name) = nvt
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("Details: {name}"));
    }

    if let Some(oid) = nvt
        .oid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("OID: {oid}"));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

pub fn finding_nvt_tag(result: &ReportResult, key: &str) -> Option<String> {
    let tags = result.nvt.as_ref()?.tags.as_deref()?;

    for part in tags.split('|') {
        let (tag_key, value) = part.split_once('=')?;

        if tag_key.trim().eq_ignore_ascii_case(key) {
            let value = value.trim();

            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

pub fn count_findings_by_threat(results: &[&ReportResult], threat: &str) -> usize {
    results
        .iter()
        .filter(|result| {
            result
                .threat
                .as_deref()
                .map(str::trim)
                .map(|value| value.eq_ignore_ascii_case(threat))
                .unwrap_or(false)
        })
        .count()
}

pub fn host_scan_window(
    report: &ReportEnvelope,
    host: &str,
) -> Option<(Option<String>, Option<String>)> {
    report
        .report
        .hosts_detail
        .iter()
        .find(|detail| detail.ip.as_deref() == Some(host))
        .map(|detail| (detail.start.clone(), detail.end.clone()))
}

#[cfg(test)]
#[path = "report_view_tests.rs"]
mod report_view_tests;
