use std::{fs, path::PathBuf};

use fpdf::Pdf;

use crate::{
    domain::report_model::ReportEnvelope,
    service::native_pdf::{document::NativePdfDocument, output::native_pdf_temp_path},
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
fn native_pdf_temp_path_uses_system_temp_dir() {
    let path = native_pdf_temp_path();

    assert!(path.starts_with(std::env::temp_dir()));
}

#[test]
fn native_pdf_temp_path_uses_pdf_extension() {
    let path = native_pdf_temp_path();

    assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("pdf"));
}

#[test]
fn native_pdf_temp_path_contains_native_pdf_prefix() {
    let path = native_pdf_temp_path();
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("temp path should have UTF-8 filename");

    assert!(filename.starts_with("gvmr-lite-rs-native-pdf-"));
    assert!(filename.ends_with(".pdf"));
}

#[test]
fn native_pdf_temp_path_contains_process_id() {
    let path = native_pdf_temp_path();
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("temp path should have UTF-8 filename");

    assert!(filename.contains(&std::process::id().to_string()));
}

#[test]
fn output_writes_reads_and_removes_pdf_file() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.write_heading("Test PDF", 1);

    let bytes = document.output().expect("PDF output should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn output_returns_valid_pdf_for_cover_page() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_cover();

    let bytes = document.output().expect("PDF output should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn output_can_be_called_for_empty_pdf_document() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    let result = document.output();

    assert!(result.is_ok());
    assert!(result.unwrap().starts_with(b"%PDF"));
}
