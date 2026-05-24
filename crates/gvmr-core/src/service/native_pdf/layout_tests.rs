use fpdf::{Pdf, Unit};

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
                <results />
            </report>
        </report>
        "#,
    )
    .expect("test report XML should parse")
}

#[test]
fn write_heading_level_1_advances_y() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_heading("Main Heading", 1);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_heading_level_2_advances_y() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_heading("Sub Heading", 2);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_heading_other_level_advances_y() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_heading("Small Heading", 3);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_heading_handles_dirty_text() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();

    document.write_heading("  Heading\nwith\tspacing  ", 1);

    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn ensure_space_does_not_add_page_when_enough_space_remains() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(Unit::mm(40.0));

    document.ensure_space(20.0);

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn ensure_space_adds_page_when_not_enough_space_remains() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(Unit::mm(280.0));

    document.ensure_space(30.0);

    assert_eq!(document.pdf.page_count(), 2);
    assert_eq!(document.pdf.page_no(), 2);
    assert!(document.pdf.ok());
}

#[test]
fn ensure_space_does_not_add_page_when_clearly_enough_space_remains() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(Unit::mm(100.0));

    document.ensure_space(20.0);

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.page_no(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn ensure_space_adds_page_when_clearly_not_enough_space_remains() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(Unit::mm(280.0));

    document.ensure_space(30.0);

    assert_eq!(document.pdf.page_count(), 2);
    assert_eq!(document.pdf.page_no(), 2);
    assert!(document.pdf.ok());
}

#[test]
fn ensure_space_adds_page_when_height_exceeds_limit_by_small_amount() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(Unit::mm(250.0));

    document.ensure_space(32.1);

    assert_eq!(document.pdf.page_count(), 2);
    assert_eq!(document.pdf.page_no(), 2);
    assert!(document.pdf.ok());
}
