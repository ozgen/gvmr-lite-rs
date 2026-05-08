use super::XmlReportRenderer;
use crate::{
    domain::report_format::ReportFormat, infra::fs::make_executable_best_effort,
    service::report_renderer::RenderError,
};
use serde_json::json;
use std::{fs, path::PathBuf};

#[tokio::test]
async fn render_report_xml_returns_error_for_invalid_xml() {
    let workdir = temp_test_dir("xml-render-invalid-xml");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'should not run'\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let err = renderer
        .render_report_xml(&fmt, "<foo></foo>", &serde_json::Map::new(), 5, None)
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::InvalidXml(_)));

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_returns_error_for_report_without_inner_report() {
    let workdir = temp_test_dir("xml-render-missing-inner-report");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'should not run'\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let err = renderer
        .render_report_xml(
            &fmt,
            r#"<report id="outer-report"></report>"#,
            &serde_json::Map::new(),
            5,
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::InvalidXml(_)));

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_returns_stdout_content() {
    let workdir = temp_test_dir("xml-render-stdout");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'hello from xml renderer'\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let result = renderer
        .render_report_xml(
            &fmt,
            valid_report_xml(),
            &serde_json::Map::new(),
            5,
            Some("custom.xml"),
        )
        .await
        .unwrap();

    assert_eq!(result.content, b"hello from xml renderer");
    assert_eq!(result.content_type, "application/xml");
    assert_eq!(result.filename, "custom.xml");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_passes_raw_xml_to_generate_script() {
    let workdir = temp_test_dir("xml-render-passes-raw-xml");

    fs::write(workdir.join("generate"), b"#!/bin/sh\ncat report.xml\n").unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let report_xml = valid_report_xml_with_result();

    let result = renderer
        .render_report_xml(&fmt, report_xml, &serde_json::Map::new(), 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, report_xml.as_bytes());
    assert_eq!(result.content_type, "application/xml");
    assert_eq!(result.filename, "report.xml");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_forwards_params_as_environment_variables() {
    let workdir = temp_test_dir("xml-render-params");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf \"%s:%s\" \"$GVMR_PARAM_FOO\" \"$GVMR_PARAM_NUMBER\"\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "txt", "text/plain");
    let renderer = XmlReportRenderer;

    let params = serde_json::Map::from_iter([
        ("foo".to_string(), json!("bar")),
        ("number".to_string(), json!(123)),
    ]);

    let result = renderer
        .render_report_xml(&fmt, valid_report_xml(), &params, 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, b"bar:123");
    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.filename, "report.txt");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_reads_output_file_when_stdout_is_empty() {
    let workdir = temp_test_dir("xml-render-output-file");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'file output' > output.xml\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let result = renderer
        .render_report_xml(&fmt, valid_report_xml(), &serde_json::Map::new(), 5, None)
        .await
        .unwrap();

    assert_eq!(result.content, b"file output");
    assert_eq!(result.content_type, "application/xml");
    assert_eq!(result.filename, "report.xml");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_returns_generate_missing_error() {
    let workdir = temp_test_dir("xml-render-missing-generate");

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let err = renderer
        .render_report_xml(&fmt, valid_report_xml(), &serde_json::Map::new(), 5, None)
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::GenerateScriptNotFound { .. }));

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_report_xml_returns_no_output_error_when_command_produces_nothing() {
    let workdir = temp_test_dir("xml-render-no-output");

    fs::write(workdir.join("generate"), b"#!/bin/sh\nexit 0\n").unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "xml", "application/xml");
    let renderer = XmlReportRenderer;

    let err = renderer
        .render_report_xml(&fmt, valid_report_xml(), &serde_json::Map::new(), 5, None)
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::NoOutput { .. }));

    let _ = fs::remove_dir_all(workdir);
}

fn valid_report_xml() -> &'static str {
    r#"<report id="outer-report" content_type="application/xml" extension="xml">
    <report id="inner-report">
        <scan_run_status>Done</scan_run_status>
        <results>
        </results>
    </report>
</report>"#
}

fn valid_report_xml_with_result() -> &'static str {
    r#"<report id="outer-report" content_type="application/xml" extension="xml"><report id="inner-report"><results><result id="result-1"><name>hello</name><host>127.0.0.1</host></result></results></report></report>"#
}

fn temp_test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gvmr-lite-rs-{name}-{}", std::process::id()));

    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    dir
}

fn test_format(workdir: PathBuf, extension: &str, content_type: &str) -> ReportFormat {
    ReportFormat::new(
        "fmt-1".to_string(),
        "Test Format".to_string(),
        extension.to_string(),
        content_type.to_string(),
        workdir,
        vec![],
    )
}
