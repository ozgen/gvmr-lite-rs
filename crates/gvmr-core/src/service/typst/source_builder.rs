use std::{fs, path::PathBuf};

use crate::domain::report_model::{ReportEnvelope, ReportResult};

use super::{
    error::TypstRenderError,
    report_view::{
        build_filter_notes, build_summary_text, count_findings_by_threat, finding_detection_method,
        finding_name, finding_nvt_tag, finding_port, finding_qod, finding_references,
        finding_severity, finding_solution, finding_threat, host_scan_window, report_timestamp,
        results_by_host,
    },
    typst_escape::{
        escape_typst_markup, optional_typst_text_expr, sanitize_typst_label, typst_string_literal,
        typst_text_expr,
    },
};

#[derive(Debug, Clone)]
pub struct TypstSourceBuilder {
    template_path: PathBuf,
}

impl TypstSourceBuilder {
    pub fn new(template_path: impl Into<PathBuf>) -> Self {
        Self {
            template_path: template_path.into(),
        }
    }

    pub fn build_report_source(&self, report: &ReportEnvelope) -> Result<String, TypstRenderError> {
        let template = self.read_template()?;

        let report_date = report_timestamp(report);
        let summary = build_summary_text(report);
        let filter_notes = build_filter_notes(report);

        let overview_table = build_host_overview_table_source(report);
        let host_authentications = build_host_authentication_source(report);
        let results_per_host = build_results_by_host_source(report);

        let source = template
            .replace("{{report_date}}", &typst_text_expr(&report_date))
            .replace("{{summary}}", &typst_text_expr(&summary))
            .replace("{{overview_table}}", &overview_table)
            .replace("{{filter_notes}}", &typst_text_expr(&filter_notes))
            .replace("{{host_authentications}}", &host_authentications)
            .replace("{{results_per_host}}", &results_per_host);

        Ok(source)
    }

    fn read_template(&self) -> Result<String, TypstRenderError> {
        fs::read_to_string(&self.template_path).map_err(|source| TypstRenderError::ReadTemplate {
            path: self.template_path.clone(),
            source,
        })
    }
}

fn build_host_overview_table_source(report: &ReportEnvelope) -> String {
    let mut rows = String::new();

    let mut total_high = 0usize;
    let mut total_medium = 0usize;
    let mut total_low = 0usize;
    let mut total_log = 0usize;
    let mut total_false_positive = 0usize;

    for (host, results) in results_by_host(report) {
        let high = count_findings_by_threat(&results, "high");
        let medium = count_findings_by_threat(&results, "medium");
        let low = count_findings_by_threat(&results, "low");
        let log = count_findings_by_threat(&results, "log");
        let false_positive = count_findings_by_threat(&results, "false positive");

        total_high += high;
        total_medium += medium;
        total_low += low;
        total_log += log;
        total_false_positive += false_positive;

        let host_label = host_label(&host);

        rows.push_str(&format!(
            "[#link(<{host_label}>)[{}]], [{}], [{}], [{}], [{}], [{}],\n",
            escape_typst_markup(&host),
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

fn build_host_authentication_source(_report: &ReportEnvelope) -> String {
    // Later: parse and render host detail entries like Auth-SSH-Success.
    String::new()
}

fn build_results_by_host_source(report: &ReportEnvelope) -> String {
    let mut out = String::new();

    for (host_index, (host, results)) in results_by_host(report).into_iter().enumerate() {
        let host_number = format!("2.{}", host_index + 1);

        out.push_str(&build_single_host_section_source(
            report,
            &host,
            &results,
            &host_number,
        ));
    }

    out
}

fn build_single_host_section_source(
    report: &ReportEnvelope,
    host: &str,
    results: &[&ReportResult],
    host_number: &str,
) -> String {
    let mut out = String::new();
    let host_label = host_label(host);

    out.push_str(&format!(
        "== {} <{}>\n\n",
        escape_typst_markup(host),
        host_label
    ));

    if let Some((start, end)) = host_scan_window(report, host) {
        if let Some(start) = start {
            out.push_str(&format!(
                "Host scan start {}\n\n",
                escape_typst_markup(&start)
            ));
        }

        if let Some(end) = end {
            out.push_str(&format!("Host scan end {}\n\n", escape_typst_markup(&end)));
        }
    }

    out.push_str(&build_host_service_table_source(host, results));
    out.push('\n');

    for (result_index, result) in results.iter().enumerate() {
        let finding_number = format!("{host_number}.{}", result_index + 1);
        let finding_label = finding_label(host, result_index);

        let title = format!(
            "{} {} {}",
            finding_number,
            finding_threat(result),
            finding_port(result)
        );

        out.push_str(&format!(
            "=== {} <{}>\n\n",
            escape_typst_markup(&title),
            finding_label
        ));

        out.push_str(&build_finding_card_source(host, result));
        out.push('\n');
    }

    out
}

fn build_host_service_table_source(host: &str, results: &[&ReportResult]) -> String {
    let mut rows = String::new();

    for (index, result) in results.iter().enumerate() {
        let finding_label = finding_label(host, index);

        rows.push_str(&format!(
            "[#link(<{}>)[{}]], [{}],\n",
            finding_label,
            escape_typst_markup(finding_port(result)),
            escape_typst_markup(finding_threat(result))
        ));
    }

    format!("#service-table((\n{rows}))\n")
}

fn build_finding_card_source(host: &str, result: &ReportResult) -> String {
    let refs = finding_references(result)
        .into_iter()
        .map(|reference| format!("  {},\n", typst_string_literal(&reference)))
        .collect::<String>();

    let references = if refs.is_empty() {
        "()".to_string()
    } else {
        format!("(\n{refs})")
    };

    let return_link = format!(
        "#link(<{}>)[return to {}]",
        host_label(host),
        escape_typst_markup(host)
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
        typst_string_literal(finding_threat(result)),
        typst_string_literal(finding_severity(result)),
        typst_string_literal(finding_name(result)),
        typst_string_literal(finding_qod(result)),
        typst_string_literal(result.description.as_deref().unwrap_or("")),
        optional_typst_text_expr(finding_nvt_tag(result, "summary")),
        optional_typst_text_expr(finding_nvt_tag(result, "impact")),
        optional_typst_text_expr(finding_solution(result)),
        optional_typst_text_expr(finding_nvt_tag(result, "insight")),
        optional_typst_text_expr(finding_detection_method(result)),
        references,
        return_link,
    )
}

fn host_label(host: &str) -> String {
    format!("host-{}", sanitize_typst_label(host))
}

fn finding_label(host: &str, index: usize) -> String {
    format!("finding-{}-{}", sanitize_typst_label(host), index + 1)
}

#[cfg(test)]
#[path = "source_builder_tests.rs"]
mod source_builder_tests;
