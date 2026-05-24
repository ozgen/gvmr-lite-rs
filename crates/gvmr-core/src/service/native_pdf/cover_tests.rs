use fpdf::Pdf;

use crate::{
    domain::report_model::ReportEnvelope,
    service::native_pdf::{document::NativePdfDocument, toc::TocEntry},
    xml::report_validator::parse_report_xml_flexible,
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
                    <full>7</full>
                    <filtered>3</filtered>
                </result_count>
                <results />
            </report>
        </report>
        "#,
    )
    .expect("test report XML should parse")
}

fn toc_entry(title: &str, page: usize) -> TocEntry {
    TocEntry {
        title: title.to_string(),
        page,
        level: 1,
        number: String::new(),
        link: 0,
    }
}

#[test]
fn write_cover_adds_cover_page() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_cover();

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_cover_accepts_empty_toc() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = Vec::new();

    document.write_cover();

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_cover_skips_toc_entries_without_page_number() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![toc_entry("Skipped Section", 0)];

    document.write_cover();

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_cover_writes_toc_entries_with_page_number() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![toc_entry("Host Summary", 2), toc_entry("Results", 5)];

    document.write_cover();

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_cover_handles_mixed_toc_entries() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![
        toc_entry("Skipped Section", 0),
        toc_entry("Included Section", 2),
    ];

    document.write_cover();

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_cover_handles_missing_report_view_optional_fields() {
    let report = parse_report_xml_flexible(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results />
            </report>
        </report>
        "#,
    )
    .expect("minimal report XML should parse");

    let mut document = NativePdfDocument::new(&report);

    document.write_cover();

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}
