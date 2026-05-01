use super::*;
use crate::xml::report_format_parser::{ParsedReportFormat, ParsedReportFormatFile};
use std::{fs, path::PathBuf};

#[test]
fn initialize_with_force_parses_xml_and_caches_format() {
    let feed_dir = temp_test_dir("init-valid-feed");
    let work_dir = temp_test_dir("init-valid-work");

    fs::write(
        feed_dir.join("format.xml"),
        r#"
        <report_format id="fmt-1">
            <name>Test Format</name>
            <extension>txt</extension>
            <content_type>text/plain</content_type>
            <report_type>scan</report_type>
            <file name="generate">aGVsbG8=</file>
        </report_format>
        "#,
    )
    .unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache.initialize_with_force(false).unwrap();

    assert!(cache.get("fmt-1").is_some());
    assert!(work_dir.join("fmt-1").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_creates_work_dir_when_feed_is_empty() {
    let feed_dir = temp_test_dir("init-empty-feed");
    let work_dir = std::env::temp_dir().join(format!(
        "gvmr-lite-rs-init-create-work-{}",
        std::process::id()
    ));

    let _ = fs::remove_dir_all(&work_dir);

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache.initialize_with_force(false).unwrap();

    assert!(work_dir.exists());
    assert!(cache.list().is_empty());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_calls_initialize_with_force_false_behavior() {
    let feed_dir = temp_test_dir("initialize-feed");
    let work_dir = temp_test_dir("initialize-work");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache.initialize().unwrap();

    assert!(cache.list().is_empty());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_true_clears_existing_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("init-force-empty-feed");
    let work_dir = temp_test_dir("init-force-empty-work");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();
    fs::write(old_workdir.join("old.txt"), b"old").unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.initialize_with_force(true).unwrap();

    assert!(cache.list().is_empty());
    assert!(!work_dir.join("old-format").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_false_keeps_existing_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("init-no-force-empty-feed");
    let work_dir = temp_test_dir("init-no-force-empty-work");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.initialize_with_force(false).unwrap();

    assert!(cache.get("old-format").is_some());
    assert!(work_dir.join("old-format").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn rebuild_uses_force_and_clears_existing_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("rebuild-empty-feed");
    let work_dir = temp_test_dir("rebuild-empty-work");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.rebuild().unwrap();

    assert!(cache.list().is_empty());
    assert!(!work_dir.join("old-format").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn list_returns_all_cached_formats() {
    let feed_dir = temp_test_dir("list-feed");
    let work_dir = temp_test_dir("list-work");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache.formats.insert(
        "fmt-1".to_string(),
        ReportFormat::new(
            "fmt-1".to_string(),
            "Format 1".to_string(),
            "txt".to_string(),
            "text/plain".to_string(),
            work_dir.join("fmt-1"),
            vec![],
        ),
    );

    cache.formats.insert(
        "fmt-2".to_string(),
        ReportFormat::new(
            "fmt-2".to_string(),
            "Format 2".to_string(),
            "html".to_string(),
            "text/html".to_string(),
            work_dir.join("fmt-2"),
            vec![],
        ),
    );

    assert_eq!(cache.list().len(), 2);
    assert!(cache.list().contains_key("fmt-1"));
    assert!(cache.list().contains_key("fmt-2"));

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn get_returns_format_by_id() {
    let feed_dir = temp_test_dir("get-feed");
    let work_dir = temp_test_dir("get-work");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache.formats.insert(
        "fmt-1".to_string(),
        ReportFormat::new(
            "fmt-1".to_string(),
            "Format 1".to_string(),
            "txt".to_string(),
            "text/plain".to_string(),
            work_dir.join("fmt-1"),
            vec![],
        ),
    );

    assert!(cache.get("fmt-1").is_some());
    assert!(cache.get("missing").is_none());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn parse_formats_skips_invalid_xml_files() {
    let feed_dir = temp_test_dir("parse-invalid-feed");
    let work_dir = temp_test_dir("parse-invalid-work");

    let invalid_xml = feed_dir.join("invalid.xml");
    fs::write(&invalid_xml, b"<report_format>").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed = cache.parse_formats(vec![invalid_xml]);

    assert!(parsed.is_empty());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn discover_xml_files_returns_only_xml_files_sorted() {
    let feed_dir = temp_test_dir("format-cache-discover-feed");
    let work_dir = temp_test_dir("format-cache-discover-work");

    fs::write(feed_dir.join("b.xml"), b"").unwrap();
    fs::write(feed_dir.join("a.xml"), b"").unwrap();
    fs::write(feed_dir.join("ignored.txt"), b"").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let files = cache.discover_xml_files().unwrap();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].file_name().unwrap(), "a.xml");
    assert_eq!(files[1].file_name().unwrap(), "b.xml");

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn discover_xml_files_returns_empty_when_feed_dir_is_missing() {
    let feed_dir = std::env::temp_dir().join("gvmr-lite-rs-missing-feed-dir");
    let work_dir = temp_test_dir("format-cache-missing-work");

    let _ = fs::remove_dir_all(&feed_dir);

    let cache = FormatCache::new(feed_dir, work_dir.clone(), false);

    let files = cache.discover_xml_files().unwrap();

    assert!(files.is_empty());

    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn handle_empty_feed_clears_formats_when_force_is_true() {
    let feed_dir = temp_test_dir("format-cache-empty-feed");
    let work_dir = temp_test_dir("format-cache-empty-work");

    fs::create_dir_all(work_dir.join("old-format")).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    cache.formats.insert(
        "old-format".to_string(),
        test_report_format(work_dir.join("old-format")),
    );

    cache.handle_empty_feed(true).unwrap();

    assert!(cache.formats.is_empty());
    assert!(!work_dir.join("old-format").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_writes_embedded_content() {
    let feed_dir = temp_test_dir("format-cache-embedded-feed");
    let work_dir = temp_test_dir("format-cache-embedded-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed_file = parsed_file_with_content("generate", b"#!/bin/sh\necho hello\n");

    let file = cache
        .cache_file(&parsed_file, &fmt_workdir, false, "fmt-1")
        .unwrap()
        .unwrap();

    assert_eq!(file.name, "generate");
    assert_eq!(
        fs::read(fmt_workdir.join("generate")).unwrap(),
        b"#!/bin/sh\necho hello\n"
    );

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_copies_external_asset_from_feed_dir() {
    let feed_dir = temp_test_dir("format-cache-copy-feed");
    let work_dir = temp_test_dir("format-cache-copy-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();
    fs::write(feed_dir.join("style.xsl"), b"asset content").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed_file = parsed_file_without_content("style.xsl");

    let file = cache
        .cache_file(&parsed_file, &fmt_workdir, false, "fmt-1")
        .unwrap()
        .unwrap();

    assert_eq!(file.name, "style.xsl");
    assert_eq!(
        fs::read(fmt_workdir.join("style.xsl")).unwrap(),
        b"asset content"
    );

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_returns_none_when_external_asset_is_missing() {
    let feed_dir = temp_test_dir("format-cache-missing-asset-feed");
    let work_dir = temp_test_dir("format-cache-missing-asset-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed_file = parsed_file_without_content("missing.xsl");

    let file = cache
        .cache_file(&parsed_file, &fmt_workdir, false, "fmt-1")
        .unwrap();

    assert!(file.is_none());
    assert!(!fmt_workdir.join("missing.xsl").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_does_not_overwrite_existing_file_without_force() {
    let feed_dir = temp_test_dir("format-cache-no-overwrite-feed");
    let work_dir = temp_test_dir("format-cache-no-overwrite-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();
    fs::write(fmt_workdir.join("generate"), b"old").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed_file = parsed_file_with_content("generate", b"new");

    cache
        .cache_file(&parsed_file, &fmt_workdir, false, "fmt-1")
        .unwrap();

    assert_eq!(fs::read(fmt_workdir.join("generate")).unwrap(), b"old");

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_overwrites_existing_file_when_force_is_true() {
    let feed_dir = temp_test_dir("format-cache-force-feed");
    let work_dir = temp_test_dir("format-cache-force-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();
    fs::write(fmt_workdir.join("generate"), b"old").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed_file = parsed_file_with_content("generate", b"new");

    cache
        .cache_file(&parsed_file, &fmt_workdir, true, "fmt-1")
        .unwrap();

    assert_eq!(fs::read(fmt_workdir.join("generate")).unwrap(), b"new");

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_overwrites_existing_file_when_rebuild_on_start_is_true() {
    let feed_dir = temp_test_dir("format-cache-rebuild-feed");
    let work_dir = temp_test_dir("format-cache-rebuild-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();
    fs::write(fmt_workdir.join("generate"), b"old").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), true);

    let parsed_file = parsed_file_with_content("generate", b"new");

    cache
        .cache_file(&parsed_file, &fmt_workdir, false, "fmt-1")
        .unwrap();

    assert_eq!(fs::read(fmt_workdir.join("generate")).unwrap(), b"new");

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_format_skips_audit_report_format() {
    let feed_dir = temp_test_dir("format-cache-skip-feed");
    let work_dir = temp_test_dir("format-cache-skip-work");

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed = parsed_format(
        "fmt-audit",
        "audit",
        vec![parsed_file_with_content("generate", b"hello")],
    );

    let result = cache.cache_format(parsed, false).unwrap();

    assert!(result.is_none());
    assert!(!work_dir.join("fmt-audit").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_format_creates_report_format_and_writes_files() {
    let feed_dir = temp_test_dir("format-cache-create-feed");
    let work_dir = temp_test_dir("format-cache-create-work");

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed = parsed_format(
        "fmt-1",
        "scan",
        vec![parsed_file_with_content("generate", b"hello")],
    );

    let format = cache.cache_format(parsed, false).unwrap().unwrap();

    assert_eq!(format.id, "fmt-1");
    assert_eq!(format.name, "Test Format");
    assert_eq!(format.extension, "txt");
    assert_eq!(format.content_type, "text/plain");
    assert_eq!(format.files.len(), 1);
    assert_eq!(fs::read(work_dir.join("fmt-1/generate")).unwrap(), b"hello");

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_format_files_deletes_stale_files_when_force_is_true() {
    let feed_dir = temp_test_dir("format-cache-stale-feed");
    let work_dir = temp_test_dir("format-cache-stale-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();
    fs::write(fmt_workdir.join("old-file"), b"old").unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false);

    let parsed = parsed_format(
        "fmt-1",
        "scan",
        vec![parsed_file_with_content("generate", b"new")],
    );

    let files = cache
        .cache_format_files(&parsed, &fmt_workdir, true)
        .unwrap();

    assert_eq!(files.len(), 1);
    assert!(fmt_workdir.join("generate").exists());
    assert!(!fmt_workdir.join("old-file").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn should_skip_report_format_returns_true_for_audit() {
    assert!(FormatCache::should_skip_report_format("fmt-1", "audit"));
    assert!(FormatCache::should_skip_report_format("fmt-1", "AUDIT"));
}

#[test]
fn should_skip_report_format_returns_false_for_normal_report_type() {
    assert!(!FormatCache::should_skip_report_format("fmt-1", "scan"));
}

fn parsed_file_with_content(name: &str, content: &[u8]) -> ParsedReportFormatFile {
    ParsedReportFormatFile {
        name: name.to_string(),
        content: Some(content.to_vec()),
    }
}

fn parsed_file_without_content(name: &str) -> ParsedReportFormatFile {
    ParsedReportFormatFile {
        name: name.to_string(),
        content: None,
    }
}

fn parsed_format(
    id: &str,
    report_type: &str,
    files: Vec<ParsedReportFormatFile>,
) -> ParsedReportFormat {
    ParsedReportFormat {
        id: id.to_string(),
        name: "Test Format".to_string(),
        extension: "txt".to_string(),
        content_type: "text/plain".to_string(),
        report_type: report_type.to_string(),
        files,
    }
}

fn test_report_format(workdir: PathBuf) -> ReportFormat {
    ReportFormat::new(
        "old-format".to_string(),
        "Old Format".to_string(),
        "txt".to_string(),
        "text/plain".to_string(),
        workdir,
        vec![],
    )
}

fn temp_test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gvmr-lite-rs-{name}-{}", std::process::id()));

    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    dir
}
