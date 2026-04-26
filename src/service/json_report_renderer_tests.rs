use super::*;
use crate::infra::fs::make_executable_best_effort;
use serde_json::json;
use std::{collections::HashSet, fs, path::PathBuf};

#[tokio::test]
async fn render_returns_error_when_generate_script_is_missing() {
    let workdir = temp_test_dir("render-missing-generate");

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
    let workdir = temp_test_dir("render-stdout");

    fs::write(
        workdir.join("generate"),
        b"#!/bin/sh\nprintf 'hello from renderer'\n",
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

    assert_eq!(result.content, b"hello from renderer");
    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.filename, "custom.txt");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_reads_output_file_when_stdout_is_empty() {
    let workdir = temp_test_dir("render-output-file");

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
    assert_eq!(result.filename, "report.txt");

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_returns_no_output_error_when_command_produces_nothing() {
    let workdir = temp_test_dir("render-no-output");

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
fn converts_param_values_to_env_strings() {
    assert_eq!(param_value_to_string(&json!("abc")), "abc");
    assert_eq!(param_value_to_string(&json!(123)), "123");
    assert_eq!(param_value_to_string(&json!(true)), "true");
    assert_eq!(param_value_to_string(&json!(null)), "");
    assert_eq!(param_value_to_string(&json!({"a": 1})), r#"{"a":1}"#);
}

#[test]
fn fallback_extension_uses_bin_for_empty_extension() {
    assert_eq!(fallback_extension(""), "bin");
    assert_eq!(fallback_extension("   "), "bin");
}

#[test]
fn fallback_extension_trims_leading_dot() {
    assert_eq!(fallback_extension(".pdf"), "pdf");
    assert_eq!(fallback_extension("html"), "html");
}

#[test]
fn walk_files_returns_empty_for_missing_dir() {
    let path = std::env::temp_dir().join("gvmr-lite-rs-missing-test-dir");

    let files = walk_files(&path).unwrap();

    assert!(files.is_empty());
}

#[test]
fn walk_files_recurses_nested_files() {
    let root = temp_test_dir("walk-files");
    let nested = root.join("a/b");

    fs::create_dir_all(&nested).unwrap();
    fs::write(root.join("root.txt"), b"root").unwrap();
    fs::write(nested.join("nested.txt"), b"nested").unwrap();

    let mut files = walk_files(&root).unwrap();
    files.sort();

    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|p| p.ends_with("root.txt")));
    assert!(files.iter().any(|p| p.ends_with("nested.txt")));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn copy_format_assets_copies_nested_files() {
    let src = temp_test_dir("copy-assets-src");
    let dst = temp_test_dir("copy-assets-dst");

    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("generate"), b"script").unwrap();
    fs::write(src.join("nested/file.txt"), b"hello").unwrap();

    let assets = copy_format_assets(&src, &dst).unwrap();

    assert!(dst.join("generate").exists());
    assert!(dst.join("nested/file.txt").exists());
    assert!(assets.contains(&dst.join("generate")));
    assert!(assets.contains(&dst.join("nested/file.txt")));

    let _ = fs::remove_dir_all(src);
    let _ = fs::remove_dir_all(dst);
}

#[test]
fn pick_output_file_prefers_changed_file_with_matching_extension() {
    let root = temp_test_dir("pick-output");

    let asset = root.join("asset.txt");
    let output_pdf = root.join("report.pdf");
    let output_txt = root.join("report.txt");

    fs::write(&asset, b"asset").unwrap();

    let before = snapshot_meta(&root);

    fs::write(&output_txt, b"text").unwrap();
    fs::write(&output_pdf, b"pdf").unwrap();

    let assets = HashSet::from([asset]);

    let picked = pick_output_file(&root, &before, &assets, Some("pdf")).unwrap();

    assert_eq!(picked, output_pdf);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn list_files_returns_relative_paths() {
    let root = temp_test_dir("list-files");

    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("nested/file.txt"), b"hello").unwrap();

    let files = list_relative_files(&root);

    assert_eq!(files, vec!["nested/file.txt"]);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn build_env_sets_expected_gvmr_variables_and_params() {
    let root = temp_test_dir("build-env");
    let report_path = root.join("report.xml");

    let fmt = ReportFormat::new(
        "fmt-1".to_string(),
        "PDF".to_string(),
        "pdf".to_string(),
        "application/pdf".to_string(),
        root.clone(),
        vec![],
    );

    let params = serde_json::Map::from_iter([
        ("foo".to_string(), json!("bar")),
        ("number".to_string(), json!(123)),
    ]);

    let envs = build_env(&fmt, &root, &report_path, &params);

    assert_eq!(envs.get("GVMR_FORMAT_ID").unwrap(), "fmt-1");
    assert_eq!(
        envs.get("GVMR_FORMAT_DIR").unwrap(),
        &root.display().to_string()
    );
    assert_eq!(
        envs.get("GVMR_WORK_DIR").unwrap(),
        &root.display().to_string()
    );
    assert_eq!(
        envs.get("GVMR_REPORT_PATH").unwrap(),
        &report_path.display().to_string()
    );
    assert_eq!(envs.get("GVMR_PARAM_FOO").unwrap(), "bar");
    assert_eq!(envs.get("GVMR_PARAM_NUMBER").unwrap(), "123");

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn make_executable_best_effort_adds_executable_bits() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_test_dir("make-executable");
    let file = root.join("generate");

    fs::write(&file, b"#!/bin/sh\n").unwrap();

    let before = fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(before & 0o111, 0);

    make_executable_best_effort(&file);

    let after = fs::metadata(&file).unwrap().permissions().mode();
    assert_ne!(after & 0o111, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn copy_dir_recursive_copies_nested_files() {
    let src = temp_test_dir("copy-dir-src");
    let dst = temp_test_dir("copy-dir-dst");

    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("root.txt"), b"root").unwrap();
    fs::write(src.join("nested/file.txt"), b"nested").unwrap();

    copy_dir_recursive(&src, &dst).unwrap();

    assert_eq!(fs::read(dst.join("root.txt")).unwrap(), b"root");
    assert_eq!(fs::read(dst.join("nested/file.txt")).unwrap(), b"nested");

    let _ = fs::remove_dir_all(src);
    let _ = fs::remove_dir_all(dst);
}

#[test]
fn current_unix_timestamp_returns_non_zero_value() {
    assert!(current_unix_timestamp() > 0);
}

#[test]
fn maybe_write_debug_json_does_nothing_without_env_var() {
    // SAFETY: this test only mutates process env for this test process.
    unsafe {
        std::env::remove_var("GVMR_RENDER_DEBUG_DIR");
    }

    maybe_write_debug_json("debug.json", &json!({ "hello": "world" }));
}

#[test]
fn maybe_write_debug_json_writes_file_when_env_var_is_set() {
    let root = temp_test_dir("debug-json");

    // SAFETY: this test only mutates process env for this test process.
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

#[test]
fn maybe_copy_debug_tmpdir_does_nothing_without_env_var() {
    unsafe {
        std::env::remove_var("GVMR_RENDER_DEBUG_DIR");
    }

    let tmpdir = temp_test_dir("debug-copy-source");
    fs::write(tmpdir.join("report.xml"), b"<report />").unwrap();

    maybe_copy_debug_tmpdir("format-1", &tmpdir);

    let _ = fs::remove_dir_all(tmpdir);
}

#[test]
fn maybe_copy_debug_tmpdir_copies_tempdir_when_env_var_is_set() {
    let source = temp_test_dir("debug-copy-source");
    let debug_root = temp_test_dir("debug-copy-root");

    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("report.xml"), b"<report />").unwrap();
    fs::write(source.join("nested/file.txt"), b"hello").unwrap();

    let format_id = format!("format-test-{}", std::process::id());

    unsafe {
        std::env::set_var("GVMR_RENDER_DEBUG_DIR", &debug_root);
    }

    maybe_copy_debug_tmpdir(&format_id, &source);

    let copied_dirs = fs::read_dir(&debug_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();

    let copied = copied_dirs
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format_id))
                && path.join("report.xml").exists()
                && path.join("nested/file.txt").exists()
        })
        .expect("expected copied debug directory");

    assert_eq!(fs::read(copied.join("report.xml")).unwrap(), b"<report />");
    assert_eq!(fs::read(copied.join("nested/file.txt")).unwrap(), b"hello");

    unsafe {
        std::env::remove_var("GVMR_RENDER_DEBUG_DIR");
    }

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(debug_root);
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
