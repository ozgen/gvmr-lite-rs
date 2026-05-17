use std::fs;

use quick_xml::de::from_str;

use super::*;
use crate::domain::report_model::ReportEnvelope;

fn parse_report(xml: &str) -> ReportEnvelope {
    from_str(xml).unwrap()
}

fn minimal_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <results>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn new_stores_process_limits() {
    let limits = TypstProcessLimits {
        enabled: true,
        use_user_scope: true,
        memory_max: "512M".to_string(),
        cpu_quota: "50%".to_string(),
        tasks_max: 64,
    };

    let renderer = TypstReportRenderer::new("missing-template.typ", limits.clone());

    assert_eq!(renderer.process_limits.enabled, limits.enabled);
    assert_eq!(
        renderer.process_limits.use_user_scope,
        limits.use_user_scope
    );
    assert_eq!(renderer.process_limits.memory_max, limits.memory_max);
    assert_eq!(renderer.process_limits.cpu_quota, limits.cpu_quota);
    assert_eq!(renderer.process_limits.tasks_max, limits.tasks_max);
}

#[test]
fn technical_report_uses_enabled_default_process_limits() {
    let renderer = TypstReportRenderer::technical_report();

    assert!(renderer.process_limits.enabled);
}

#[test]
fn technical_report_without_limits_disables_process_limits() {
    let renderer = TypstReportRenderer::technical_report_without_limits();

    assert!(!renderer.process_limits.enabled);
}

#[test]
fn render_returns_read_template_error_when_template_is_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let template_path = temp_dir.path().join("missing-template.typ");

    let renderer = TypstReportRenderer::new(&template_path, TypstProcessLimits::disabled());

    let report = minimal_report();

    let result = renderer.render(&report);

    match result {
        Err(TypstRenderError::ReadTemplate { path, .. }) => {
            assert_eq!(path, template_path);
        }
        other => panic!("expected ReadTemplate error, got {other:?}"),
    }
}

#[test]
fn read_pdf_returns_pdf_bytes() {
    let temp_dir = tempfile::tempdir().unwrap();
    let pdf_path = temp_dir.path().join("report.pdf");

    fs::write(&pdf_path, b"%PDF fake pdf bytes").unwrap();

    let renderer = TypstReportRenderer::new(
        temp_dir.path().join("template.typ"),
        TypstProcessLimits::disabled(),
    );

    let bytes = renderer.read_pdf(&pdf_path).unwrap();

    assert_eq!(bytes, b"%PDF fake pdf bytes");
}

#[test]
fn read_pdf_returns_read_pdf_error_when_file_is_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let pdf_path = temp_dir.path().join("missing.pdf");

    let renderer = TypstReportRenderer::new(
        temp_dir.path().join("template.typ"),
        TypstProcessLimits::disabled(),
    );

    let result = renderer.read_pdf(&pdf_path);

    match result {
        Err(TypstRenderError::ReadPdf { path, .. }) => {
            assert_eq!(path, pdf_path);
        }
        other => panic!("expected ReadPdf error, got {other:?}"),
    }
}

#[test]
fn render_in_work_dir_maps_write_source_error() {
    let temp_dir = tempfile::tempdir().unwrap();

    let renderer = TypstReportRenderer::new(
        temp_dir.path().join("template.typ"),
        TypstProcessLimits::disabled(),
    );

    let not_a_directory = temp_dir.path().join("not-a-directory");
    fs::write(&not_a_directory, b"file, not directory").unwrap();

    let result = renderer.render_in_work_dir("hello".to_string(), &not_a_directory);

    match result {
        Err(TypstRenderError::WriteSource { path, .. }) => {
            assert_eq!(path, not_a_directory.join("report.typ"));
        }
        other => panic!("expected WriteSource error, got {other:?}"),
    }
}
