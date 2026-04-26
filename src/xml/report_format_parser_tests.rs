use super::*;
use base64::{Engine, engine::general_purpose};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn write_temp_xml(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gvmr-lite-rs-test-{}", std::process::id()));

    fs::create_dir_all(&dir).unwrap();

    let path = dir.join(name);
    fs::write(&path, content).unwrap();

    path
}

fn remove_file(path: &Path) {
    let _ = fs::remove_file(path);
}

#[test]
fn parses_valid_report_format_xml() {
    let encoded = general_purpose::STANDARD.encode("hello");

    let path = write_temp_xml(
        "valid-report-format.xml",
        &format!(
            r#"
            <report_format id="abc-123">
                <name>PDF</name>
                <extension>pdf</extension>
                <content_type>application/pdf</content_type>
                <report_type>scan</report_type>
                <file name="generate">{encoded}</file>
            </report_format>
            "#
        ),
    );

    let parsed = parse_report_format_xml(&path).unwrap();

    assert_eq!(parsed.id, "abc-123");
    assert_eq!(parsed.name, "PDF");
    assert_eq!(parsed.extension, "pdf");
    assert_eq!(parsed.content_type, "application/pdf");
    assert_eq!(parsed.report_type, "scan");
    assert_eq!(parsed.files.len(), 1);
    assert_eq!(parsed.files[0].name, "generate");
    assert_eq!(
        parsed.files[0].content.as_deref(),
        Some(b"hello".as_slice())
    );

    remove_file(&path);
}

#[test]
fn defaults_missing_report_type_to_scan() {
    let encoded = general_purpose::STANDARD.encode("hello");

    let path = write_temp_xml(
        "missing-report-type.xml",
        &format!(
            r#"
            <report_format id="abc-123">
                <name>PDF</name>
                <extension>pdf</extension>
                <content_type>application/pdf</content_type>
                <file name="generate">{encoded}</file>
            </report_format>
            "#
        ),
    );

    let parsed = parse_report_format_xml(&path).unwrap();

    assert_eq!(parsed.report_type, "scan");

    remove_file(&path);
}

#[test]
fn parses_empty_file_as_none_content() {
    let path = write_temp_xml(
        "empty-file.xml",
        r#"
        <report_format id="abc-123">
            <name>PDF</name>
            <extension>pdf</extension>
            <content_type>application/pdf</content_type>
            <file name="generate"></file>
        </report_format>
        "#,
    );

    let parsed = parse_report_format_xml(&path).unwrap();

    assert_eq!(parsed.files.len(), 1);
    assert_eq!(parsed.files[0].name, "generate");
    assert!(parsed.files[0].content.is_none());

    remove_file(&path);
}

#[test]
fn returns_missing_report_format_id_error() {
    let path = write_temp_xml(
        "missing-id.xml",
        r#"
        <report_format>
            <name>PDF</name>
            <extension>pdf</extension>
            <content_type>application/pdf</content_type>
            <file name="generate"></file>
        </report_format>
        "#,
    );

    let err = parse_report_format_xml(&path).unwrap_err();

    assert!(matches!(
        err,
        ReportFormatParseError::MissingAttribute("report_format@id")
    ));

    remove_file(&path);
}

#[test]
fn returns_missing_file_name_error() {
    let path = write_temp_xml(
        "missing-file-name.xml",
        r#"
        <report_format id="abc-123">
            <name>PDF</name>
            <extension>pdf</extension>
            <content_type>application/pdf</content_type>
            <file></file>
        </report_format>
        "#,
    );

    let err = parse_report_format_xml(&path).unwrap_err();

    assert!(matches!(
        err,
        ReportFormatParseError::MissingAttribute("file@name")
    ));

    remove_file(&path);
}

#[test]
fn returns_invalid_base64_error() {
    let path = write_temp_xml(
        "invalid-base64.xml",
        r#"
        <report_format id="abc-123">
            <name>PDF</name>
            <extension>pdf</extension>
            <content_type>application/pdf</content_type>
            <file name="generate">not valid base64 !</file>
        </report_format>
        "#,
    );

    let err = parse_report_format_xml(&path).unwrap_err();

    match err {
        ReportFormatParseError::InvalidBase64 { file_name, .. } => {
            assert_eq!(file_name, "generate");
        }
        other => panic!("expected InvalidBase64, got {other:?}"),
    }

    remove_file(&path);
}

#[test]
fn returns_missing_file_error_when_no_file_entries_exist() {
    let path = write_temp_xml(
        "missing-file.xml",
        r#"
        <report_format id="abc-123">
            <name>PDF</name>
            <extension>pdf</extension>
            <content_type>application/pdf</content_type>
        </report_format>
        "#,
    );

    let err = parse_report_format_xml(&path).unwrap_err();

    assert!(matches!(err, ReportFormatParseError::MissingField("file")));

    remove_file(&path);
}

#[test]
fn returns_read_error_for_missing_path() {
    let path = std::env::temp_dir().join("definitely-missing-report-format.xml");

    let err = parse_report_format_xml(&path).unwrap_err();

    assert!(matches!(err, ReportFormatParseError::Read(_)));
}
