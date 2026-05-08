use super::{JsonReportRenderer, maybe_write_debug_json};
use crate::{
    domain::report_format::ReportFormat,
    infra::fs::make_executable_best_effort,
    service::report_renderer::{RenderError, ReportRenderer},
};
use serde_json::json;
use std::{fs, path::PathBuf, sync::Mutex};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[tokio::test]
async fn render_returns_error_when_generate_script_is_missing() {
    let workdir = temp_test_dir("json-render-missing-generate");

    let fmt = test_format(workdir.clone(), "txt", "text/plain");
    let renderer = JsonReportRenderer;

    let err = renderer
        .render(
            &fmt,
            &json!({ "results": { "result": [] } }),
            &serde_json::Map::new(),
            5,
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::GenerateScriptNotFound { .. }));

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_returns_stdout_content() {
    let workdir = temp_test_dir("json-render-stdout");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'hello from json renderer'\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "txt", "text/plain");
    let renderer = JsonReportRenderer;

    let result = renderer
        .render(
            &fmt,
            &json!({ "results": { "result": [] } }),
            &serde_json::Map::new(),
            5,
            Some("custom.txt"),
        )
        .await
        .unwrap();

    assert_eq!(result.content, b"hello from json renderer");
    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.filename, "custom.txt");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_reads_output_file_when_stdout_is_empty() {
    let workdir = temp_test_dir("json-render-output-file");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'file output' > report.txt\n",
    )
    .unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "txt", "text/plain");
    let renderer = JsonReportRenderer;

    let result = renderer
        .render(
            &fmt,
            &json!({ "results": { "result": [] } }),
            &serde_json::Map::new(),
            5,
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.content, b"file output");
    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.filename, "report.txt");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_uses_default_content_type_when_format_content_type_is_empty() {
    let workdir = temp_test_dir("json-render-empty-content-type");

    fs::write(workdir.join("generate"), b"#!/bin/sh\nprintf 'hello'\n").unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "txt", "");
    let renderer = JsonReportRenderer;

    let result = renderer
        .render(
            &fmt,
            &json!({ "results": { "result": [] } }),
            &serde_json::Map::new(),
            5,
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.content, b"hello");
    assert_eq!(result.content_type, "application/octet-stream");
    assert_eq!(result.filename, "report.txt");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_returns_no_output_error_when_command_produces_nothing() {
    let workdir = temp_test_dir("json-render-no-output");

    fs::write(workdir.join("generate"), b"#!/bin/sh\nexit 0\n").unwrap();

    make_executable_best_effort(&workdir.join("generate"));

    let fmt = test_format(workdir.clone(), "txt", "text/plain");
    let renderer = JsonReportRenderer;

    let err = renderer
        .render(
            &fmt,
            &json!({ "results": { "result": [] } }),
            &serde_json::Map::new(),
            5,
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(err, RenderError::NoOutput { .. }));

    let _ = fs::remove_dir_all(workdir);
}

#[test]
fn maybe_write_debug_json_does_nothing_without_env_var() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    unsafe {
        std::env::remove_var("GVMR_RENDER_DEBUG_DIR");
    }

    maybe_write_debug_json("debug.json", &json!({ "hello": "world" }));
}

#[test]
fn maybe_write_debug_json_writes_file_when_env_var_is_set() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let root = temp_test_dir("json-debug-json");

    unsafe {
        std::env::set_var("GVMR_RENDER_DEBUG_DIR", &root);
    }

    maybe_write_debug_json("debug.json", &json!({ "hello": "world" }));

    let written = fs::read_to_string(root.join("debug.json")).unwrap();

    assert!(written.contains("\"hello\""));
    assert!(written.contains("\"world\""));

    unsafe {
        std::env::remove_var("GVMR_RENDER_DEBUG_DIR");
    }

    let _ = fs::remove_dir_all(root);
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
