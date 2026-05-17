use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    domain::report_model::{ReportEnvelope, ReportResult},
    infra::fs::{ensure_dir, write_bytes_atomic},
    service::typst::error::TypstRenderError,
};

#[derive(Debug, Clone)]
pub struct TypstPdfRenderer {
    template_path: PathBuf,
}

impl TypstPdfRenderer {
    pub fn new(template_path: impl Into<PathBuf>) -> Self {
        Self {
            template_path: template_path.into(),
        }
    }

    pub fn technical() -> Self {
        Self::new("templates/typst/technical.typ")
    }

    pub fn render(&self, report: &ReportEnvelope) -> Result<Vec<u8>, TypstRenderError> {
        let typst_source = self.build_typst_source(report)?;

        let work_dir = typst_work_dir();
        ensure_dir(&work_dir).map_err(|source| TypstRenderError::CreateWorkDir {
            path: work_dir.clone(),
            source,
        })?;

        let typst_path = work_dir.join("report.typ");
        let pdf_path = work_dir.join("report.pdf");

        write_bytes_atomic(&typst_path, typst_source.as_bytes()).map_err(|source| {
            TypstRenderError::WriteSource {
                path: typst_path.clone(),
                source,
            }
        })?;

        let output = Command::new("typst")
            .arg("compile")
            .arg(&typst_path)
            .arg(&pdf_path)
            .output()
            .map_err(TypstRenderError::RunTypst)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            return Err(TypstRenderError::TypstFailed(format!(
                "{stderr}\n{stdout}"
            )));
        }

        let pdf = fs::read(&pdf_path).map_err(|source| TypstRenderError::ReadPdf {
            path: pdf_path,
            source,
        })?;

        let _ = fs::remove_dir_all(&work_dir);

        Ok(pdf)
    }
    pub fn build_typst_source(
        &self,
        report: &ReportEnvelope,
    ) -> Result<String, TypstRenderError> {
        let template = fs::read_to_string(&self.template_path).map_err(|source| {
            TypstRenderError::ReadTemplate {
                path: self.template_path.clone(),
                source,
            }
        })?;

        let report_date = report_date(report);
        let summary = summary_text(report);
        let filter_notes = filter_notes(report);
        let overview_table = build_overview_table(report);
        let host_authentications = build_host_authentications(report);
        let results_per_host = build_results_per_host(report);

        let source = template
            .replace("{{report_date}}", &typst_content(&report_date))
            .replace("{{summary}}", &typst_content(&summary))
            .replace("{{overview_table}}", &overview_table)
            .replace("{{filter_notes}}", &typst_content(&filter_notes))
            .replace("{{host_authentications}}", &host_authentications)
            .replace("{{results_per_host}}", &results_per_host);

        Ok(source)
    }
}

fn report_date(report: &ReportEnvelope) -> String {
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

fn summary_text(report: &ReportEnvelope) -> String {
    let timezone = report.report.timezone.as_deref().unwrap_or("unknown");
    let timezone_abbrev = report.report.timezone_abbrev.as_deref().unwrap_or("");
    let task = task_name(report);
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

fn task_name(report: &ReportEnvelope) -> &str {
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

fn all_results(report: &ReportEnvelope) -> &[ReportResult] {
    report
        .report
        .results
        .as_ref()
        .map(|results| results.result.as_slice())
        .unwrap_or_default()
}

fn grouped_results(report: &ReportEnvelope) -> BTreeMap<String, Vec<&ReportResult>> {
    let mut grouped = BTreeMap::new();

    for result in all_results(report) {
        grouped
            .entry(result_host(result).to_string())
            .or_insert_with(Vec::new)
            .push(result);
    }

    grouped
}

fn build_overview_table(report: &ReportEnvelope) -> String {
    let mut rows = String::new();

    let mut total_high = 0usize;
    let mut total_medium = 0usize;
    let mut total_low = 0usize;
    let mut total_log = 0usize;
    let mut total_false_positive = 0usize;

    for (host, results) in grouped_results(report) {
        let high = count_threat(&results, "high");
        let medium = count_threat(&results, "medium");
        let low = count_threat(&results, "low");
        let log = count_threat(&results, "log");
        let false_positive = count_threat(&results, "false positive");

        total_high += high;
        total_medium += medium;
        total_low += low;
        total_log += log;
        total_false_positive += false_positive;

        let host_label = host_label(&host);

        rows.push_str(&format!(
            "[#link(<{host_label}>)[{}]], [{}], [{}], [{}], [{}], [{}],\n",
            typst_escape(&host),
            high,
            medium,
            low,
            log,
            false_positive
        ));
    }

    rows.push_str(&format!(
        "[*Total*], [*{}*], [*{}*], [*{}*], [*{}*], [*{}*],\n",
        total_high, total_medium, total_low, total_log, total_false_positive
    ));

    format!("#overview-table((\n{rows}))")
}

fn filter_notes(report: &ReportEnvelope) -> String {
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

fn build_host_authentications(_report: &ReportEnvelope) -> String {
    // We can add this after parsing host detail entries like Auth-SSH-Success.
    String::new()
}

fn build_results_per_host(report: &ReportEnvelope) -> String {
    let mut out = String::new();

    for (host_index, (host, results)) in grouped_results(report).into_iter().enumerate() {
        let host_number = format!("2.{}", host_index + 1);
        let host_label = host_label(&host);

        out.push_str(&format!("== {} <{}>\n\n", typst_escape(&host), host_label));

        if let Some((start, end)) = host_scan_times(report, &host) {
            if let Some(start) = start {
                out.push_str(&format!("Host scan start {}\n\n", typst_escape(&start)));
            }

            if let Some(end) = end {
                out.push_str(&format!("Host scan end {}\n\n", typst_escape(&end)));
            }
        }

        out.push_str(&build_service_table(&host, &results));
        out.push('\n');

        for (result_index, result) in results.iter().enumerate() {
            let finding_number = format!("{host_number}.{}", result_index + 1);
            let finding_label = finding_label(&host, result_index);
            let title = format!(
                "{} {} {}",
                finding_number,
                result_threat(result),
                result_port(result)
            );

            out.push_str(&format!(
                "=== {} <{}>\n\n",
                typst_escape(&title),
                finding_label
            ));

            out.push_str(&build_finding_card(&host, result_index, result));
            out.push('\n');
        }
    }

    out
}

fn build_service_table(host: &str, results: &[&ReportResult]) -> String {
    let mut rows = String::new();

    for (index, result) in results.iter().enumerate() {
        let finding_label = finding_label(host, index);

        rows.push_str(&format!(
            "[#link(<{}>)[{}]], [{}],\n",
            finding_label,
            typst_escape(result_port(result)),
            typst_escape(result_threat(result))
        ));
    }

    format!("#service-table((\n{rows}))\n")
}

fn build_finding_card(host: &str, _index: usize, result: &ReportResult) -> String {
    let refs = result_references(result)
    .into_iter()
    .map(|reference| format!("  {},\n", typst_string(&reference)))
    .collect::<String>();

    let references = if refs.is_empty() {
        "()".to_string()
    } else {
        format!("(\n{refs})")
    };

    let return_link = format!(
        "#link(<{}>)[return to {}]",
        host_label(host),
        typst_escape(host)
    );

    format!(
    "#finding-card(\n\
  threat: {},\n\
  severity: {},\n\
  nvt: {},\n\
  qod: {},\n\
  detection-result: {},\n\
  summary: {},\n\
  impact: {},\n\
  solution: {},\n\
  insight: {},\n\
  detection-method: {},\n\
  references: {},\n\
  return-link: [{}],\n\
)\n",
    typst_string(result_threat(result)),
    typst_string(result_severity(result)),
    typst_string(result_name(result)),
    typst_string(result_qod(result)),
    typst_string(result.description.as_deref().unwrap_or("")),
    optional_typst_content(nvt_tag(result, "summary")),
    optional_typst_content(nvt_tag(result, "impact")),
    optional_typst_content(result_solution(result)),
    optional_typst_content(nvt_tag(result, "insight")),
    optional_typst_content(detection_method(result)),
    references,
    return_link,
)
}

fn result_host(result: &ReportResult) -> &str {
    result
        .host
        .as_ref()
        .and_then(|host| host.text.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
}

fn result_port(result: &ReportResult) -> &str {
    result
        .port
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("general/tcp")
}

fn result_threat(result: &ReportResult) -> &str {
    result
        .threat
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Log")
}

fn result_severity(result: &ReportResult) -> &str {
    result
        .severity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
}

fn result_qod(result: &ReportResult) -> &str {
    result
        .qod
        .as_ref()
        .and_then(|qod| qod.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
}

fn result_name(result: &ReportResult) -> &str {
    result
        .nvt
        .as_ref()
        .and_then(|nvt| nvt.name.as_deref())
        .or(result.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Finding")
}

fn result_solution(result: &ReportResult) -> Option<String> {
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

fn result_references(result: &ReportResult) -> Vec<String> {
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
                        .filter(|v| !v.is_empty())
                    {
                        Some(kind) => Some(format!("{kind}: {id}")),
                        None => Some(id.to_string()),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn detection_method(result: &ReportResult) -> Option<String> {
    let nvt = result.nvt.as_ref()?;

    let mut parts = Vec::new();

    if let Some(method) = nvt_tag(result, "vuldetect") {
        parts.push(method);
    }

    if let Some(name) = nvt.name.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        parts.push(format!("Details: {name}"));
    }

    if let Some(oid) = nvt.oid.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        parts.push(format!("OID: {oid}"));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

fn nvt_tag(result: &ReportResult, key: &str) -> Option<String> {
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

fn count_threat(results: &[&ReportResult], threat: &str) -> usize {
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

fn host_scan_times(
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

fn host_label(host: &str) -> String {
    format!("host-{}", typst_label(host))
}

fn finding_label(host: &str, index: usize) -> String {
    format!("finding-{}-{}", typst_label(host), index + 1)
}

fn typst_label(value: &str) -> String {
    let mut out = String::new();

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }

    while out.contains("--") {
        out = out.replace("--", "-");
    }

    let cleaned = out.trim_matches('-');

    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned.to_string()
    }
}

fn typst_content(value: &str) -> String {
    format!("#text({})", typst_string(value))
}

fn optional_typst_content(value: Option<String>) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => typst_string(&value),
        _ => "none".to_string(),
    }
}

fn typst_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');

    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => {}
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }

    escaped.push('"');
    escaped
}

fn typst_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('#', "\\#")
}

fn typst_work_dir() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    let pid = std::process::id();

    std::env::temp_dir().join(format!("gvmr-lite-rs-typst-{pid}-{millis}"))
}
