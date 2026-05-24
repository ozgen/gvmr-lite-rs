use std::collections::{BTreeMap, BTreeSet};

use chrono::Datelike;

use crate::domain::report_model::{InnerReport, ReportResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportTargetKind {
    Host,
    ContainerImage,
    Agent,
}

impl ReportTargetKind {
    pub fn from_report(report: &InnerReport) -> Self {
        if report.is_container_image_report() {
            Self::ContainerImage
        } else if report.is_agent_report() {
            Self::Agent
        } else {
            Self::Host
        }
    }

    pub fn overview_column(self) -> &'static str {
        match self {
            Self::Host => "Host",
            Self::ContainerImage => "Image",
            Self::Agent => "Agent",
        }
    }

    pub fn results_section_title(self) -> &'static str {
        match self {
            Self::Host => "Results per Host",
            Self::ContainerImage => "Results per Image",
            Self::Agent => "Results per Agent",
        }
    }

    pub fn scan_start_label(self) -> &'static str {
        match self {
            Self::Host => "Host scan start",
            Self::ContainerImage => "Image scan start",
            Self::Agent => "Agent scan start",
        }
    }

    pub fn scan_end_label(self) -> &'static str {
        match self {
            Self::Host => "Host scan end",
            Self::ContainerImage => "Image scan end",
            Self::Agent => "Agent scan end",
        }
    }

    pub fn singular_name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ContainerImage => "image",
            Self::Agent => "agent",
        }
    }

    pub fn plural_name(self) -> &'static str {
        match self {
            Self::Host => "hosts",
            Self::ContainerImage => "images",
            Self::Agent => "agents",
        }
    }

    pub fn result_targets_only_text(self) -> String {
        format!("It only lists {} that produced issues.", self.plural_name())
    }

    pub fn finding_title(self, result: &ReportResult) -> String {
        let threat = result_threat(result);

        match self {
            Self::Host => format!("{threat} {}", result_port(result)),
            Self::ContainerImage | Self::Agent => threat.to_string(),
        }
    }

    pub fn is_grouped_by_threat(self) -> bool {
        matches!(self, Self::ContainerImage | Self::Agent)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReportView<'a> {
    report: &'a InnerReport,
    target_kind: ReportTargetKind,
}

impl<'a> ReportView<'a> {
    pub fn new(report: &'a InnerReport, target_kind: ReportTargetKind) -> Self {
        Self {
            report,
            target_kind,
        }
    }

    pub fn from_report(report: &'a InnerReport) -> Self {
        Self::new(report, ReportTargetKind::from_report(report))
    }

    pub fn report(&self) -> &'a InnerReport {
        self.report
    }

    pub fn target_kind(&self) -> ReportTargetKind {
        self.target_kind
    }

    pub fn report_timestamp(&self) -> String {
        report_timestamp(self.report)
    }

    pub fn report_date(&self) -> String {
        report_date(self.report)
    }

    pub fn task_name(&self) -> &'a str {
        task_name(self.report)
    }

    pub fn summary_text(&self) -> String {
        summary_text(self.report, self.target_kind)
    }

    pub fn filter_summary_text(&self) -> String {
        build_filter_summary_text(self.report, self.target_kind)
    }

    pub fn all_results(&self) -> Vec<&'a ReportResult> {
        all_results(self.report)
    }

    pub fn grouped_results_by_target(&self) -> BTreeMap<String, Vec<ReportResult>> {
        group_results_by_target(self.report, self.target_kind)
    }

    pub fn overview_rows(&self) -> Vec<Vec<String>> {
        build_overview_rows(self.report, self.target_kind)
    }

    pub fn overview_column(&self) -> &'static str {
        self.target_kind.overview_column()
    }

    pub fn results_section_title(&self) -> &'static str {
        self.target_kind.results_section_title()
    }

    pub fn scan_start_label(&self) -> &'static str {
        self.target_kind.scan_start_label()
    }

    pub fn scan_end_label(&self) -> &'static str {
        self.target_kind.scan_end_label()
    }
}

pub fn report_timestamp(report: &InnerReport) -> String {
    report
        .timestamp
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
        .to_string()
}

pub fn report_date(report: &InnerReport) -> String {
    let timestamp = report_timestamp(report);

    if timestamp.trim().is_empty() {
        String::new()
    } else {
        format_report_date(&timestamp)
    }
}

pub fn task_name(report: &InnerReport) -> &str {
    report
        .task
        .as_ref()
        .and_then(|task| task.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Unknown task")
}

pub fn summary_text(report: &InnerReport, target_kind: ReportTargetKind) -> String {
    let timezone = report
        .timezone
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("GMT");

    let timezone_abbrev = report
        .timezone_abbrev
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("UTC");

    let scan_start = report
        .scan_start
        .as_deref()
        .map(format_summary_datetime)
        .unwrap_or_else(|| "unknown".to_string());

    let scan_end = report
        .scan_end
        .as_deref()
        .map(format_summary_datetime)
        .unwrap_or_else(|| "unknown".to_string());

    format!(
        "This document reports on the results of an automatic security scan. \
All dates are displayed using the timezone \"{timezone}\", which is abbreviated \"{timezone_abbrev}\". \
The task was \"{}\". The scan started at {scan_start} and ended at {scan_end}. \
The report first summarises the results found. Then, for each {}, the report describes every issue found. \
Please consider the advice given in each description, in order to rectify the issue.",
        task_name(report),
        target_kind.singular_name()
    )
}

pub fn all_results(report: &InnerReport) -> Vec<&ReportResult> {
    report
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

pub fn group_results_by_target(
    report: &InnerReport,
    target_kind: ReportTargetKind,
) -> BTreeMap<String, Vec<ReportResult>> {
    let mut grouped: BTreeMap<String, Vec<ReportResult>> = BTreeMap::new();

    for result in all_results(report) {
        grouped
            .entry(result_target_name(result, target_kind).to_string())
            .or_default()
            .push(result.clone());
    }

    grouped
}

pub fn group_results_by_host(report: &InnerReport) -> BTreeMap<String, Vec<ReportResult>> {
    group_results_by_target(report, ReportTargetKind::Host)
}

pub fn build_overview_rows(
    report: &InnerReport,
    target_kind: ReportTargetKind,
) -> Vec<Vec<String>> {
    let grouped = group_results_by_target(report, target_kind);

    let mut rows = Vec::new();

    let mut total_critical = 0usize;
    let mut total_high = 0usize;
    let mut total_medium = 0usize;
    let mut total_low = 0usize;
    let mut total_log = 0usize;
    let mut total_false_positive = 0usize;

    for (target_name, results) in grouped {
        let critical = count_threat(&results, "critical");
        let high = count_threat(&results, "high");
        let medium = count_threat(&results, "medium");
        let low = count_threat(&results, "low");
        let log = count_threat(&results, "log");
        let false_positive = count_threat(&results, "false positive");

        total_critical += critical;
        total_high += high;
        total_medium += medium;
        total_low += low;
        total_log += log;
        total_false_positive += false_positive;

        rows.push(vec![
            target_name,
            critical.to_string(),
            high.to_string(),
            medium.to_string(),
            low.to_string(),
            log.to_string(),
            false_positive.to_string(),
        ]);
    }

    rows.push(vec![
        "Total".to_string(),
        total_critical.to_string(),
        total_high.to_string(),
        total_medium.to_string(),
        total_low.to_string(),
        total_log.to_string(),
        total_false_positive.to_string(),
    ]);

    rows
}

pub fn count_threat(results: &[ReportResult], threat: &str) -> usize {
    results
        .iter()
        .filter(|result| result_threat(result).eq_ignore_ascii_case(threat))
        .count()
}

pub fn result_target_name(result: &ReportResult, target_kind: ReportTargetKind) -> &str {
    match target_kind {
        ReportTargetKind::Host | ReportTargetKind::Agent => result_host(result),
        ReportTargetKind::ContainerImage => result
            .target_display_name()
            .or_else(|| result.image_full_name())
            .or_else(|| result.image_digest())
            .unwrap_or_else(|| result_host(result)),
    }
}

pub fn image_display_name(result: &ReportResult) -> String {
    result
        .target_display_name()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| result_host(result).to_string())
}

pub fn grouped_threats(results: &[ReportResult]) -> Vec<String> {
    let mut seen = BTreeSet::new();

    for result in results {
        let threat = result_threat(result).trim();

        if !threat.is_empty() {
            seen.insert(threat.to_string());
        }
    }

    let order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Log",
        "False Positive",
        "False P.",
    ];

    let mut ordered = Vec::new();

    for threat in order {
        if seen.remove(threat) {
            ordered.push(threat.to_string());
        }
    }

    ordered.extend(seen);
    ordered
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

pub fn result_summary(result: &ReportResult) -> Option<String> {
    nvt_tag(result, "summary").or_else(|| {
        result
            .description
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

pub fn result_impact(result: &ReportResult) -> Option<String> {
    nvt_tag(result, "impact")
}

pub fn result_affected(result: &ReportResult) -> Option<String> {
    nvt_tag(result, "affected")
}

pub fn result_insight(result: &ReportResult) -> Option<String> {
    nvt_tag(result, "insight")
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

pub fn filter_keyword_value(report: &InnerReport, column: &str) -> Option<String> {
    report
        .filters
        .as_ref()?
        .keywords
        .as_ref()?
        .keyword
        .iter()
        .find(|keyword| {
            keyword
                .column
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| value.eq_ignore_ascii_case(column))
        })?
        .value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn build_filter_summary_text(report: &InnerReport, target_kind: ReportTargetKind) -> String {
    let mut lines = Vec::new();

    match filter_keyword_value(report, "autofp").as_deref() {
        Some("1") => {
            lines.push("Vendor security updates are trusted, using full CVE matching.".to_string())
        }
        Some("2") => lines
            .push("Vendor security updates are trusted, using partial CVE matching.".to_string()),
        _ => lines.push("Vendor security updates are not trusted.".to_string()),
    }

    match filter_keyword_value(report, "apply_overrides").as_deref() {
        Some("1") => lines.push(
            "Overrides are on. When a result has an override, this report uses the threat of the override."
                .to_string(),
        ),
        _ => lines.push(
            "Overrides are off. Even when a result has an override, this report uses the actual threat of the result."
                .to_string(),
        ),
    }

    match filter_keyword_value(report, "overrides").as_deref() {
        Some("0") => {
            lines.push("Information on overrides is excluded from the report.".to_string())
        }
        _ => lines.push("Information on overrides is included in the report.".to_string()),
    }

    match filter_keyword_value(report, "notes").as_deref() {
        Some("0") => lines.push("Notes are excluded from the report.".to_string()),
        _ => lines.push("Notes are included in the report.".to_string()),
    }

    lines.push("This report might not show details of all issues that were found.".to_string());

    if filter_keyword_value(report, "result_hosts_only").as_deref() == Some("1") {
        lines.push(target_kind.result_targets_only_text());
    }

    if let Some(term) = report
        .filters
        .as_ref()
        .and_then(|filters| filters.term.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!(
            "It shows issues that contain the search phrase \"{term}\"."
        ));
    }

    if let Some(levels) = filter_keyword_value(report, "levels") {
        append_missing_threat_level_text(&mut lines, &levels);
    }

    match filter_keyword_value(report, "min_qod").as_deref() {
        Some("0") => {}
        Some(value) if !value.trim().is_empty() => {
            lines.push(format!(
                "Only results with a minimum QoD of {value} are shown."
            ));
        }
        _ => {
            lines.push("Only results with a minimum QoD of 70 are shown.".to_string());
        }
    }

    lines.push(result_count_summary_text(report));

    lines.join("\n")
}

pub fn result_count_summary_text(report: &InnerReport) -> String {
    let shown_count = report
        .results
        .as_ref()
        .map(|results| results.result.len())
        .unwrap_or(0);

    let start = report
        .results
        .as_ref()
        .and_then(|results| results.start.as_deref())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);

    let filtered_count = report
        .result_count
        .as_ref()
        .and_then(|count| count.filtered.as_deref())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(shown_count);

    let full_count = report
        .result_count
        .as_ref()
        .and_then(|count| count.full.as_deref())
        .and_then(|value| value.parse::<usize>().ok());

    let last = if shown_count == 0 {
        0
    } else {
        start + shown_count - 1
    };

    let mut text = if shown_count == 0 {
        "This report contains 0 results.".to_string()
    } else if shown_count == filtered_count {
        format!(
            "This report contains all {filtered_count} results selected by the filtering described above."
        )
    } else if shown_count == 1 {
        format!(
            "This report contains result {last} of the {filtered_count} results selected by the filtering above."
        )
    } else {
        format!(
            "This report contains results {start} to {last} of the {filtered_count} results selected by the filtering described above."
        )
    };

    if let Some(full_count) = full_count {
        text.push_str(&format!(
            " Before filtering there were {full_count} results."
        ));
    }

    text
}

fn append_missing_threat_level_text(lines: &mut Vec<String>, levels: &str) {
    let levels = levels.trim();

    if levels.is_empty() {
        return;
    }

    let checks = [
        ('c', "Critical"),
        ('h', "High"),
        ('m', "Medium"),
        ('l', "Low"),
        ('g', "Log"),
        ('d', "Debug"),
        ('f', "False Positive"),
    ];

    for (flag, label) in checks {
        if !levels.contains(flag) {
            lines.push(format!(
                "Issues with the threat level \"{label}\" are not shown."
            ));
        }
    }
}

pub fn host_scan_window(
    report: &InnerReport,
    host: &str,
) -> Option<(Option<String>, Option<String>)> {
    report
        .hosts_detail
        .iter()
        .find(|detail| detail.ip.as_deref() == Some(host))
        .map(|detail| (detail.start.clone(), detail.end.clone()))
}

pub fn format_report_date(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| {
            let date = date.date_naive();
            format!("{} {}, {}", date.format("%B"), date.day(), date.year())
        })
        .unwrap_or_else(|_| clean_report_text(value))
}

pub fn format_summary_datetime(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| {
            date.with_timezone(&chrono::Utc)
                .format("%a %b %e %H:%M:%S %Y UTC")
                .to_string()
                .replace("  ", " ")
        })
        .unwrap_or_else(|_| clean_report_text(value))
}

pub fn clean_report_text(value: &str) -> String {
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

#[cfg(test)]
#[path = "report_view_tests.rs"]
mod report_view_tests;
