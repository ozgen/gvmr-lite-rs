use super::*;

use crate::{
    domain::report_model::ReportEnvelope, service::native_pdf::document::NativePdfDocument,
    xml::report_validator::parse_report_xml_flexible,
};

fn test_report() -> ReportEnvelope {
    parse_report_xml_flexible(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
            </report>
        </report>
        "#,
    )
    .expect("test report XML should parse")
}

#[test]
fn delta_marker_maps_all_states() {
    assert_eq!(delta_marker(DeltaState::Same), "=");
    assert_eq!(delta_marker(DeltaState::New), "+");
    assert_eq!(delta_marker(DeltaState::Gone), "-");
    assert_eq!(delta_marker(DeltaState::Changed), "~");
}

#[test]
fn classify_diff_line_maps_diff_prefixes() {
    assert_eq!(classify_diff_line("@@ -1 +1 @@"), DiffLineKind::Hunk);
    assert_eq!(classify_diff_line("+new value"), DiffLineKind::Added);
    assert_eq!(classify_diff_line("-old value"), DiffLineKind::Removed);
    assert_eq!(classify_diff_line(" unchanged"), DiffLineKind::Context);
    assert_eq!(classify_diff_line("+++ file"), DiffLineKind::Context);
    assert_eq!(classify_diff_line("--- file"), DiffLineKind::Context);
}

#[test]
fn diff_line_fill_maps_each_diff_kind() {
    assert_eq!(
        diff_line_fill(DiffLineKind::Hunk),
        fpdf::RGB::new(238, 232, 248)
    );
    assert_eq!(
        diff_line_fill(DiffLineKind::Removed),
        fpdf::RGB::new(252, 230, 230)
    );
    assert_eq!(
        diff_line_fill(DiffLineKind::Added),
        fpdf::RGB::new(226, 244, 228)
    );
    assert_eq!(
        diff_line_fill(DiffLineKind::Context),
        fpdf::RGB::new(255, 255, 255)
    );
}

#[test]
fn write_delta_marker_handles_all_states() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    for state in [
        DeltaState::Same,
        DeltaState::New,
        DeltaState::Gone,
        DeltaState::Changed,
    ] {
        document.write_delta_marker(state);
    }

    assert!(document.pdf.ok());
    assert_eq!(document.pdf.page_count(), 1);
}

#[test]
fn write_diff_block_handles_all_line_kinds_and_blank_lines() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_diff_block("@@ -1 +1 @@\n-old value\n+new value\n unchanged\n");

    assert!(document.pdf.ok());
    assert_eq!(document.pdf.page_count(), 1);
}

#[test]
fn write_diff_block_handles_multiline_diff() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_diff_block("@@ -1,2 +1,3 @@\n-old\n+new\n context\n\n+another");

    assert!(document.pdf.ok());
}

#[test]
fn write_diff_block_wraps_long_lines() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    let long_line = format!("+{}", "long value ".repeat(500));
    document.write_diff_block(&long_line);

    assert!(document.pdf.ok());
}

#[test]
fn write_diff_block_handles_empty_input() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_diff_block("");

    assert!(document.pdf.ok());
}

fn report_with_baseline(baseline: &str) -> ReportEnvelope {
    parse_report_xml_flexible(&format!(
        r#"
        <report>
            <report id="current-report" type="delta">
                <delta>{baseline}</delta>
                <results />
            </report>
        </report>
        "#
    ))
    .expect("delta report should parse")
}

#[test]
fn write_delta_report_metadata_renders_full_baseline() {
    let report = report_with_baseline(
        r#"
        <report id="baseline-report">
            <scan_run_status>Done</scan_run_status>
            <timestamp>2026-08-01T12:00:00Z</timestamp>
            <scan_start>2026-08-01T11:00:00Z</scan_start>
            <scan_end>2026-08-01T11:30:00Z</scan_end>
        </report>
        "#,
    );
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
}

#[test]
fn write_delta_report_metadata_handles_id_only_baseline() {
    let report = report_with_baseline(r#"<report id="baseline-report" />"#);
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
}

#[test]
fn write_delta_report_metadata_handles_timestamp_only_baseline() {
    let report = report_with_baseline(
        r#"
        <report>
            <timestamp>2026-08-01T12:00:00Z</timestamp>
            <scan_start>2026-08-01T11:00:00Z</scan_start>
        </report>
        "#,
    );
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
}

#[test]
fn write_delta_report_metadata_handles_missing_baseline_report() {
    let report = report_with_baseline("");
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
}

#[test]
fn write_delta_report_metadata_handles_delta_without_report_level_delta() {
    let report = parse_report_xml_flexible(
        r#"
        <report>
            <report id="current-report" type="delta">
                <results />
            </report>
        </report>
        "#,
    )
    .expect("delta report should parse");
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
}

#[test]
fn write_delta_report_metadata_handles_ordinary_report() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
}

#[test]
fn write_delta_report_metadata_supports_compliance_delta_reports() {
    let report = parse_report_xml_flexible(
        r#"
        <report>
            <report id="audit-delta-report" type="delta">
                <compliance_count><filtered>1</filtered></compliance_count>
                <delta>
                    <report id="baseline-audit-report">
                        <scan_run_status>Done</scan_run_status>
                    </report>
                </delta>
                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <compliance>yes</compliance>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
    .expect("compliance delta report should parse");
    let mut document = NativePdfDocument::new(&report);
    document.pdf.add_page();

    document.write_delta_report_metadata();

    assert!(document.pdf.ok());
}
