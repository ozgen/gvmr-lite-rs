use fpdf::{Pdf, Unit};

use crate::{
    domain::report_model::ReportEnvelope, service::native_pdf::document::NativePdfDocument,
    service::report_view::ReportTargetKind, xml::report_validator::parse_report_xml_flexible,
};

fn test_report() -> ReportEnvelope {
    parse_report_xml_flexible(
        r#"
        <report>
            <report id="inner-report-id">
                <timestamp>2024-01-02T05:04:05Z</timestamp>
                <timezone>GMT</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2024-01-02T03:04:05Z</scan_start>
                <scan_end>2024-01-02T04:04:05Z</scan_end>
                <scan_run_status>Done</scan_run_status>
                <task>
                    <name>Test Task</name>
                </task>
                <host>
                    <ip>192.0.2.10</ip>
                </host>
                <result_count>
                    <full>0</full>
                    <filtered>0</filtered>
                </result_count>
                <results />
            </report>
        </report>
        "#,
    )
    .expect("test report XML should parse")
}

fn delta_report() -> ReportEnvelope {
    parse_report_xml_flexible(
        r#"
        <report>
            <report id="current-report" type="delta">
                <timestamp>2026-09-02T09:32:31Z</timestamp>
                <scan_start>2026-09-02T09:32:29Z</scan_start>
                <scan_end>2026-09-02T09:32:31Z</scan_end>
                <delta>
                    <report id="baseline-report">
                        <scan_run_status>Done</scan_run_status>
                        <timestamp>2026-09-01T09:32:31Z</timestamp>
                        <scan_start>2026-09-01T09:32:29Z</scan_start>
                        <scan_end>2026-09-01T09:32:31Z</scan_end>
                    </report>
                </delta>
                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Delta finding</name>
                        <threat>High</threat>
                        <severity>8.0</severity>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
    .expect("delta report should parse")
}

#[test]
fn new_initializes_pdf_document_state() {
    let report = test_report();

    let mut document = NativePdfDocument::new(&report);

    assert_eq!(
        document.report.report.id.as_deref(),
        Some("inner-report-id")
    );
    assert!(document.host_links.is_empty());
    assert!(document.finding_links.is_empty());
    assert!(document.toc.is_empty());

    assert_eq!(document.pdf.page_count(), 0);
    assert_eq!(document.pdf.page_no(), 0);
    assert!(document.pdf.ok());
}

#[test]
fn new_initializes_report_view() {
    let report = test_report();

    let document = NativePdfDocument::new(&report);

    assert_eq!(
        document.view.report().id.as_deref(),
        Some("inner-report-id")
    );
    assert_eq!(document.view.task_name(), "Test Task");
    assert_eq!(document.view.report_date(), "January 2, 2024");
}

#[test]
fn new_sets_target_from_report() {
    let report = test_report();

    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::Host);
    assert_eq!(document.view.target_kind(), ReportTargetKind::Host);
}

#[test]
fn render_returns_pdf_bytes() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    let bytes = document.render().expect("native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_adds_pages() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    let bytes = document.render().expect("native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(document.pdf.page_count() >= 1);
    assert!(document.pdf.ok());
}

#[test]
fn render_delta_report_starts_results_after_cover() {
    let report = delta_report();
    let mut document = NativePdfDocument::new(&report);

    document.prepare_toc(None);
    let bytes = document
        .render()
        .expect("native delta PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert_eq!(document.pdf.page_count(), 3);
    assert_eq!(document.toc[0].title, "Result Overview");
    assert_eq!(document.toc[0].page, 2);
    assert_eq!(document.toc[1].title, "Results per Host");
    assert_eq!(document.toc[1].page, 3);
    assert_eq!(document.toc[2].page, 3);
    assert!(document.pdf.ok());
}

#[test]
fn set_link_here_sets_link_on_current_page() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let link = document.pdf.add_link();
    document.pdf.set_y(Unit::mm(42.0));

    document.set_link_here(link, 1);

    assert!(document.pdf.ok());
    assert_eq!(document.pdf.page_no(), 1);
}

#[test]
fn set_link_here_clamps_negative_y_to_zero() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let link = document.pdf.add_link();
    document.pdf.set_y(Unit::mm(-10.0));

    document.set_link_here(link, 1);

    assert!(document.pdf.ok());
    assert_eq!(document.pdf.page_no(), 1);
}
