use fpdf::{Pdf, Unit};

use crate::{
    domain::report_model::ReportEnvelope,
    service::native_pdf::{document::NativePdfDocument, target::ReportTargetKind},
    xml::report_validator::parse_report_xml_flexible,
};

fn test_report() -> ReportEnvelope {
    parse_report_xml_flexible(
        r#"
        <report>
            <report id="inner-report-id">
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
fn new_sets_target_kind_from_report() {
    let report = test_report();

    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target_kind, ReportTargetKind::Host);
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
