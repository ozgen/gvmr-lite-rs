use super::AuditReportRenderer;

use std::{fs, path::PathBuf};

use serde_json::{Map, Value, json};

use crate::{
    domain::{audit_report_model::AuditReportEnvelope, report_format::ReportFormat},
    infra::fs::make_executable_best_effort,
    service::report_renderer::RenderError,
};

fn renderer() -> AuditReportRenderer {
    AuditReportRenderer
}

fn valid_audit_report_json() -> Value {
    json!({
        "@attrs": {
            "id": "outer-report"
        },
        "name": "Audit Report",
        "report": {
            "scan_run_status": "Done",
            "timestamp": "2026-06-04T10:00:00Z",
            "results": {
                "result": []
            }
        }
    })
}

fn valid_audit_report_model() -> AuditReportEnvelope {
    serde_json::from_value(valid_audit_report_json())
        .expect("valid audit report JSON should deserialize into AuditReportEnvelope")
}

fn feed_format(script: &[u8], extension: &str, content_type: &str) -> ReportFormat {
    let workdir = temp_test_dir("audit-report-renderer-format");
    let generate_path = workdir.join("generate");

    fs::write(&generate_path, script).unwrap();
    make_executable_best_effort(&generate_path);

    ReportFormat::feed(
        "audit-format-1".to_string(),
        "Audit Report Format".to_string(),
        extension.to_string(),
        content_type.to_string(),
        workdir,
        vec![],
    )
}

fn feed_format_without_generate() -> ReportFormat {
    let workdir = temp_test_dir("audit-report-renderer-missing-generate");

    ReportFormat::feed(
        "audit-format-1".to_string(),
        "Audit Report Format".to_string(),
        "pdf".to_string(),
        "application/pdf".to_string(),
        workdir,
        vec![],
    )
}

fn temp_test_dir(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let dir = std::env::temp_dir().join(format!(
        "gvmr-lite-rs-{name}-{}-{unique}",
        std::process::id()
    ));

    fs::create_dir_all(&dir).unwrap();

    dir
}

#[tokio::test]
async fn render_report_json_returns_stdout_content() {
    let fmt = feed_format(
        b"#!/bin/sh\nprintf 'fake audit pdf from json'\n",
        "pdf",
        "application/pdf",
    );

    let result = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &Map::new(), 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, b"fake audit pdf from json");
    assert_eq!(result.content_type, "application/pdf");
    assert_eq!(result.filename, "report.pdf");
}

#[tokio::test]
async fn render_report_json_uses_output_name() {
    let fmt = feed_format(
        b"#!/bin/sh\nprintf 'fake audit pdf'\n",
        "pdf",
        "application/pdf",
    );

    let result = renderer()
        .render_report_json(
            &fmt,
            &valid_audit_report_json(),
            &Map::new(),
            5,
            Some("custom-audit-report.pdf"),
        )
        .await
        .unwrap();

    assert_eq!(result.content, b"fake audit pdf");
    assert_eq!(result.content_type, "application/pdf");
    assert_eq!(result.filename, "custom-audit-report.pdf");
}

#[tokio::test]
async fn render_report_json_forwards_params_to_generate_script() {
    let fmt = feed_format(
        b"#!/bin/sh\nprintf \"%s:%s\" \"$GVMR_PARAM_TIMEZONE\" \"$GVMR_PARAM_DEBUG\"\n",
        "txt",
        "text/plain",
    );

    let mut params = Map::new();
    params.insert(
        "timezone".to_string(),
        Value::String("Europe/Berlin".to_string()),
    );
    params.insert("debug".to_string(), Value::Bool(true));

    let result = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &params, 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, b"Europe/Berlin:true");
    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.filename, "report.txt");
}

#[tokio::test]
async fn render_report_json_passes_generated_xml_to_feed_pipeline() {
    let fmt = feed_format(b"#!/bin/sh\ncat report.xml\n", "xml", "application/xml");

    let result = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &Map::new(), 5, None)
        .await
        .unwrap();

    let xml = String::from_utf8(result.content).unwrap();
    let trimmed_xml = xml.trim_start();

    assert_eq!(result.content_type, "application/xml");
    assert_eq!(result.filename, "report.xml");

    assert!(
        trimmed_xml.starts_with("<report") || trimmed_xml.starts_with("<?xml"),
        "unexpected XML output: {trimmed_xml}"
    );
    assert!(trimmed_xml.contains("<report"));
    assert!(trimmed_xml.contains("Done"));
}

#[tokio::test]
async fn render_report_json_reads_output_file_when_stdout_is_empty() {
    let fmt = feed_format(
        b"#!/bin/sh\nprintf 'file output from audit renderer' > output.pdf\n",
        "pdf",
        "application/pdf",
    );

    let result = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &Map::new(), 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, b"file output from audit renderer");
    assert_eq!(result.content_type, "application/pdf");
    assert_eq!(result.filename, "report.pdf");
}

#[tokio::test]
async fn render_report_json_returns_error_when_generate_script_is_missing() {
    let fmt = feed_format_without_generate();

    let err = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &Map::new(), 5, None)
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::GenerateScriptNotFound { .. }));
}

#[tokio::test]
async fn render_report_json_returns_error_when_generate_script_fails() {
    let fmt = feed_format(
        b"#!/bin/sh\nprintf 'fake generate failure' >&2\nexit 1\n",
        "pdf",
        "application/pdf",
    );

    let err = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &Map::new(), 5, None)
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::NoOutput { .. }));
}

#[tokio::test]
async fn render_report_json_returns_error_when_generate_script_produces_no_output() {
    let fmt = feed_format(b"#!/bin/sh\nexit 0\n", "pdf", "application/pdf");

    let err = renderer()
        .render_report_json(&fmt, &valid_audit_report_json(), &Map::new(), 5, None)
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::NoOutput { .. }));
}

#[tokio::test]
async fn render_report_returns_stdout_content() {
    let fmt = feed_format(
        b"#!/bin/sh\nprintf 'fake audit pdf from model'\n",
        "pdf",
        "application/pdf",
    );

    let report = valid_audit_report_model();

    let result = renderer()
        .render_report(&fmt, &report, &Map::new(), 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, b"fake audit pdf from model");
    assert_eq!(result.content_type, "application/pdf");
    assert_eq!(result.filename, "report.pdf");
}

#[tokio::test]
async fn render_report_passes_normalized_feed_xml_to_generate_script() {
    let fmt = feed_format(b"#!/bin/sh\ncat report.xml\n", "xml", "application/xml");

    let report = valid_audit_report_model();

    let result = renderer()
        .render_report(&fmt, &report, &Map::new(), 5, None)
        .await
        .unwrap();

    let xml = String::from_utf8(result.content).unwrap();

    assert_eq!(result.content_type, "application/xml");
    assert_eq!(result.filename, "report.xml");

    assert!(xml.starts_with("<report"));
    assert!(xml.contains("Done"));
}
