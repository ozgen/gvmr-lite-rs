use std::collections::BTreeMap;

use crate::domain::report_model::{ReportEnvelope, ReportResult};
use chrono::Datelike;

pub const MAX_FIELD_CHARS: usize = 6_000;

pub fn all_results(report: &ReportEnvelope) -> Vec<&ReportResult> {
    report
        .report
        .results
        .as_ref()
        .map(|results| {
            results
                .result
                .iter()
                .filter(|result| should_render_result(result))
                .collect()
        })
        .unwrap_or_default()
}

pub fn should_render_result(result: &ReportResult) -> bool {
    let threat = result_threat(result);

    !(threat.eq_ignore_ascii_case("info")
        || threat.eq_ignore_ascii_case("debug")
        || threat.eq_ignore_ascii_case("false positive"))
}

pub fn group_results_by_host(report: &ReportEnvelope) -> BTreeMap<String, Vec<ReportResult>> {
    let mut grouped: BTreeMap<String, Vec<ReportResult>> = BTreeMap::new();

    for result in all_results(report).into_iter() {
        grouped
            .entry(result_host(result).to_string())
            .or_default()
            .push(result.clone());
    }

    grouped
}

pub fn build_overview_rows(report: &ReportEnvelope) -> Vec<Vec<String>> {
    let grouped = group_results_by_host(report);

    let mut rows = Vec::new();

    let mut total_critical = 0usize;
    let mut total_high = 0usize;
    let mut total_medium = 0usize;
    let mut total_low = 0usize;
    let mut total_log = 0usize;

    for (host, results) in grouped {
        let critical = count_threat(&results, "critical");
        let high = count_threat(&results, "high");
        let medium = count_threat(&results, "medium");
        let low = count_threat(&results, "low");
        let log = count_threat(&results, "log");

        total_critical += critical;
        total_high += high;
        total_medium += medium;
        total_low += low;
        total_log += log;

        rows.push(vec![
            host,
            critical.to_string(),
            high.to_string(),
            medium.to_string(),
            low.to_string(),
            log.to_string(),
        ]);
    }

    rows.push(vec![
        "Total".to_string(),
        total_critical.to_string(),
        total_high.to_string(),
        total_medium.to_string(),
        total_low.to_string(),
        total_log.to_string(),
    ]);

    rows
}

pub fn count_threat(results: &[ReportResult], threat: &str) -> usize {
    results
        .iter()
        .filter(|result| result_threat(result).eq_ignore_ascii_case(threat))
        .count()
}

pub fn result_host(result: &ReportResult) -> &str {
    result
        .host
        .as_ref()
        .and_then(|host| host.text.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
}

pub fn result_port(result: &ReportResult) -> &str {
    result
        .port
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("general/tcp")
}

pub fn result_threat(result: &ReportResult) -> &str {
    result
        .threat
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Log")
}

pub fn result_severity(result: &ReportResult) -> &str {
    result
        .severity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
}

pub fn result_qod(result: &ReportResult) -> &str {
    result
        .qod
        .as_ref()
        .and_then(|qod| qod.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
}

pub fn result_name(result: &ReportResult) -> &str {
    result
        .nvt
        .as_ref()
        .and_then(|nvt| nvt.name.as_deref())
        .or(result.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Finding")
}

pub fn result_solution(result: &ReportResult) -> Option<String> {
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

pub fn result_references(result: &ReportResult) -> Vec<String> {
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

pub fn detection_method(result: &ReportResult) -> Option<String> {
    let nvt = result.nvt.as_ref()?;

    let mut parts = Vec::new();

    if let Some(method) = nvt_tag(result, "vuldetect") {
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

pub fn nvt_tag(result: &ReportResult, key: &str) -> Option<String> {
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

pub fn report_date(report: &ReportEnvelope) -> String {
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

pub fn task_name(report: &ReportEnvelope) -> &str {
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

pub fn summary_text(report: &ReportEnvelope) -> String {
    let timezone_abbrev = report
        .report
        .timezone_abbrev
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("UTC");

    let scan_start = report
        .report
        .scan_start
        .as_deref()
        .map(format_summary_datetime)
        .unwrap_or_else(|| "unknown".to_string());

    let scan_end = report
        .report
        .scan_end
        .as_deref()
        .map(format_summary_datetime)
        .unwrap_or_else(|| "unknown".to_string());

    format!(
        "This document reports on the results of an automatic security scan. \
All dates are displayed using the timezone \"GMT\", which is abbreviated \"{timezone_abbrev}\". \
The task was \"{}\". The scan started at {scan_start} and ended at {scan_end}. \
The report first summarises the results found. Then, for each host, the report describes every issue found. \
Please consider the advice given in each description, in order to rectify the issue.",
        task_name(report)
    )
}

pub fn severity_color(threat: &str) -> (u8, u8, u8) {
    match threat.trim().to_ascii_lowercase().as_str() {
        "critical" => (139, 0, 0),
        "high" => (220, 20, 60),
        "medium" => (255, 140, 0),
        "low" => (80, 160, 200),
        "log" => (30, 144, 255),
        _ => (100, 100, 100),
    }
}

pub fn estimate_line_count(text: &str, chars_per_line: usize) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    text.lines()
        .map(|line| {
            let len = line.chars().count();

            if len == 0 {
                1
            } else {
                len.div_ceil(chars_per_line)
            }
        })
        .sum()
}

pub fn truncate_text(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();

    if count <= max_chars {
        return value.to_string();
    }

    let mut out = value.chars().take(max_chars).collect::<String>();
    out.push_str("\n\n[truncated]");
    out
}

pub fn clean_text(value: &str) -> String {
    value
        .replace('\u{0000}', "")
        .replace(['“', '”'], "\"")
        .replace(['‘', '’'], "'")
        .replace(['–', '—'], "-")
        .replace('…', "...")
        .chars()
        .filter(|ch| *ch == '\n' || *ch == '\t' || !ch.is_control())
        .collect()
}

pub fn wrap_text(text: &str, chars_per_line: usize) -> Vec<String> {
    let mut lines = Vec::new();

    for paragraph in text.split('\n') {
        let paragraph = paragraph.trim();

        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut line = String::new();

        for word in paragraph.split_whitespace() {
            let extra_space = usize::from(!line.is_empty());

            if line.chars().count() + word.chars().count() + extra_space > chars_per_line
                && !line.is_empty()
            {
                lines.push(line);
                line = String::new();
            }

            if !line.is_empty() {
                line.push(' ');
            }

            line.push_str(word);
        }

        if !line.is_empty() {
            lines.push(line);
        }
    }

    lines
}

pub fn format_report_date(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| {
            let date = date.date_naive();
            format!("{} {}, {}", date.format("%B"), date.day(), date.year())
        })
        .unwrap_or_else(|_| clean_text(value))
}

fn format_summary_datetime(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| {
            date.with_timezone(&chrono::Utc)
                .format("%a %b %e %H:%M:%S %Y UTC")
                .to_string()
                .replace("  ", " ")
        })
        .unwrap_or_else(|_| clean_text(value))
}

#[cfg(test)]
#[path = "pdf_renderer_helper_tests.rs"]
mod pdf_renderer_helper_tests;
