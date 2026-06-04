use super::*;
use crate::{
    domain::report_format_constants::{
        BUILT_IN_NATIVE_PDF_TECHNICAL_ID, BUILT_IN_TYPST_TECHNICAL_ID,
    },
    xml::report_format_parser::{ParsedReportFormat, ParsedReportFormatFile},
};
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

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.initialize_with_force(false).unwrap();

    assert!(cache.get("fmt-1").is_some());
    assert!(cache.get(BUILT_IN_TYPST_TECHNICAL_ID).is_some());
    assert!(cache.get(BUILT_IN_NATIVE_PDF_TECHNICAL_ID).is_some());

    assert!(work_dir.join("fmt-1").exists());
    assert!(work_dir.join(BUILT_IN_TYPST_TECHNICAL_ID).exists());
    assert!(work_dir.join(BUILT_IN_NATIVE_PDF_TECHNICAL_ID).exists());

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

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.initialize_with_force(false).unwrap();

    assert!(work_dir.exists());
    assert_eq!(cache.list().len(), 2);
    assert_built_in_formats_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_calls_initialize_with_force_false_behavior() {
    let feed_dir = temp_test_dir("initialize-feed");
    let work_dir = temp_test_dir("initialize-work");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.initialize().unwrap();

    assert_eq!(cache.list().len(), 2);
    assert_built_in_formats_registered(&cache, &work_dir);

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

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.initialize_with_force(true).unwrap();

    assert_eq!(cache.list().len(), 2);
    assert!(cache.get("old-format").is_none());
    assert!(!work_dir.join("old-format").exists());
    assert_built_in_formats_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_false_keeps_existing_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("init-no-force-empty-feed");
    let work_dir = temp_test_dir("init-no-force-empty-work");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.initialize_with_force(false).unwrap();

    assert_eq!(cache.list().len(), 3);
    assert!(cache.get("old-format").is_some());
    assert!(work_dir.join("old-format").exists());
    assert_built_in_formats_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn rebuild_uses_force_and_clears_existing_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("rebuild-empty-feed");
    let work_dir = temp_test_dir("rebuild-empty-work");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.rebuild().unwrap();

    assert_eq!(cache.list().len(), 2);
    assert!(cache.get("old-format").is_none());
    assert!(!work_dir.join("old-format").exists());
    assert_built_in_formats_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn list_returns_all_cached_formats() {
    let feed_dir = temp_test_dir("list-feed");
    let work_dir = temp_test_dir("list-work");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.formats.insert(
        "fmt-1".to_string(),
        ReportFormat::feed(
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
        ReportFormat::feed(
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

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.formats.insert(
        "fmt-1".to_string(),
        ReportFormat::feed(
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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir, work_dir.clone(), false, true);

    let files = cache.discover_xml_files().unwrap();

    assert!(files.is_empty());

    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn handle_empty_feed_clears_formats_when_force_is_true() {
    let feed_dir = temp_test_dir("format-cache-empty-feed");
    let work_dir = temp_test_dir("format-cache-empty-work");

    fs::create_dir_all(work_dir.join("old-format")).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.formats.insert(
        "old-format".to_string(),
        test_report_format(work_dir.join("old-format")),
    );

    cache.handle_empty_feed(true).unwrap();

    assert_eq!(cache.list().len(), 2);
    assert!(cache.get("old-format").is_none());
    assert!(!work_dir.join("old-format").exists());
    assert_built_in_formats_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn handle_empty_feed_keeps_formats_when_force_is_false() {
    let feed_dir = temp_test_dir("format-cache-empty-feed-no-force");
    let work_dir = temp_test_dir("format-cache-empty-work-no-force");

    fs::create_dir_all(work_dir.join("old-format")).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

    cache.formats.insert(
        "old-format".to_string(),
        test_report_format(work_dir.join("old-format")),
    );

    cache.handle_empty_feed(false).unwrap();

    assert_eq!(cache.list().len(), 3);
    assert!(cache.get("old-format").is_some());
    assert!(work_dir.join("old-format").exists());
    assert_built_in_formats_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_file_writes_embedded_content() {
    let feed_dir = temp_test_dir("format-cache-embedded-feed");
    let work_dir = temp_test_dir("format-cache-embedded-work");
    let fmt_workdir = work_dir.join("fmt-1");

    fs::create_dir_all(&fmt_workdir).unwrap();

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), true, true);

    let parsed_file = parsed_file_with_content("generate", b"new");

    cache
        .cache_file(&parsed_file, &fmt_workdir, false, "fmt-1")
        .unwrap();

    assert_eq!(fs::read(fmt_workdir.join("generate")).unwrap(), b"new");

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn cache_format_creates_report_format_and_writes_files() {
    let feed_dir = temp_test_dir("format-cache-create-feed");
    let work_dir = temp_test_dir("format-cache-create-work");

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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

    let cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, true);

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
fn initialize_with_empty_feed_does_not_register_built_ins_when_experimental_is_false() {
    let feed_dir = temp_test_dir("init-empty-feed-no-experimental");
    let work_dir = temp_test_dir("init-empty-work-no-experimental");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache.initialize().unwrap();

    assert!(work_dir.exists());
    assert_eq!(cache.list().len(), 0);
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_missing_feed_does_not_register_built_ins_when_experimental_is_false() {
    let root_dir = temp_test_dir("missing-feed-root-no-experimental");
    let feed_dir = root_dir.join("missing-feed");
    let work_dir = root_dir.join("work");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache.initialize().unwrap();

    assert!(work_dir.exists());
    assert_eq!(cache.list().len(), 0);
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(root_dir);
}

#[test]
fn initialize_with_valid_feed_caches_feed_format_only_when_experimental_is_false() {
    let feed_dir = temp_test_dir("init-valid-feed-no-experimental");
    let work_dir = temp_test_dir("init-valid-work-no-experimental");

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

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache.initialize().unwrap();

    assert_eq!(cache.list().len(), 1);
    assert!(cache.get("fmt-1").is_some());
    assert!(work_dir.join("fmt-1").exists());
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_true_clears_existing_formats_and_does_not_register_built_ins_when_experimental_is_false()
 {
    let feed_dir = temp_test_dir("init-force-empty-feed-no-experimental");
    let work_dir = temp_test_dir("init-force-empty-work-no-experimental");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();
    fs::write(old_workdir.join("old.txt"), b"old").unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.initialize_with_force(true).unwrap();

    assert_eq!(cache.list().len(), 0);
    assert!(cache.get("old-format").is_none());
    assert!(!work_dir.join("old-format").exists());
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_false_keeps_existing_formats_but_does_not_register_built_ins_when_experimental_is_false()
 {
    let feed_dir = temp_test_dir("init-no-force-empty-feed-no-experimental");
    let work_dir = temp_test_dir("init-no-force-empty-work-no-experimental");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.initialize_with_force(false).unwrap();

    assert_eq!(cache.list().len(), 1);
    assert!(cache.get("old-format").is_some());
    assert!(work_dir.join("old-format").exists());
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn rebuild_does_not_register_built_ins_when_experimental_is_false() {
    let feed_dir = temp_test_dir("rebuild-empty-feed-no-experimental");
    let work_dir = temp_test_dir("rebuild-empty-work-no-experimental");

    let old_workdir = work_dir.join("old-format");
    fs::create_dir_all(&old_workdir).unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache
        .formats
        .insert("old-format".to_string(), test_report_format(old_workdir));

    cache.rebuild().unwrap();

    assert_eq!(cache.list().len(), 0);
    assert!(cache.get("old-format").is_none());
    assert!(!work_dir.join("old-format").exists());
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn register_built_in_formats_is_noop_when_experimental_is_false() {
    let feed_dir = temp_test_dir("register-builtins-feed-no-experimental");
    let work_dir = temp_test_dir("register-builtins-work-no-experimental");

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache.register_built_in_formats().unwrap();

    assert_eq!(cache.list().len(), 0);
    assert_built_in_formats_not_registered(&cache, &work_dir);

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_routes_audit_formats_to_audit_cache() {
    let feed_dir = temp_test_dir("init-audit-feed");
    let work_dir = temp_test_dir("init-audit-work");

    fs::write(
        feed_dir.join("scan-format.xml"),
        r#"
        <report_format id="scan-fmt-1">
            <name>Scan Format</name>
            <extension>txt</extension>
            <content_type>text/plain</content_type>
            <report_type>scan</report_type>
            <file name="scan-generate">c2Nhbg==</file>
        </report_format>
        "#,
    )
    .unwrap();

    fs::write(
        feed_dir.join("audit-format.xml"),
        r#"
        <report_format id="audit-fmt-1">
            <name>Audit Format</name>
            <extension>xml</extension>
            <content_type>text/xml</content_type>
            <report_type>audit</report_type>
            <file name="audit-generate">YXVkaXQ=</file>
        </report_format>
        "#,
    )
    .unwrap();

    let mut cache = FormatCache::new(feed_dir.clone(), work_dir.clone(), false, false);

    cache.initialize_with_force(false).unwrap();

    assert!(cache.get("scan-fmt-1").is_some());
    assert!(cache.contains("scan-fmt-1"));
    assert_eq!(cache.list().len(), 1);

    assert!(cache.get_audit("audit-fmt-1").is_some());
    assert!(cache.contains_audit("audit-fmt-1"));
    assert_eq!(cache.list_audit().len(), 1);

    assert!(cache.get("audit-fmt-1").is_none());
    assert!(!cache.contains("audit-fmt-1"));

    assert!(cache.get_audit("scan-fmt-1").is_none());
    assert!(!cache.contains_audit("scan-fmt-1"));

    assert!(work_dir.join("scan-fmt-1").exists());
    assert!(work_dir.join("audit-fmt-1").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_true_clears_existing_audit_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("init-force-empty-audit-feed");
    let work_dir = temp_test_dir("init-force-empty-audit-work");

    let old_scan_workdir = work_dir.join("old-scan-format");
    let old_audit_workdir = work_dir.join("old-audit-format");

    fs::create_dir_all(&old_scan_workdir).unwrap();
    fs::create_dir_all(&old_audit_workdir).unwrap();

    fs::write(old_scan_workdir.join("old-scan.txt"), b"old scan").unwrap();
    fs::write(old_audit_workdir.join("old-audit.txt"), b"old audit").unwrap();

    let mut formats = HashMap::new();
    formats.insert(
        "old-scan-format".to_string(),
        test_report_format(old_scan_workdir.clone()),
    );

    let mut audit_formats = HashMap::new();
    audit_formats.insert(
        "old-audit-format".to_string(),
        test_report_format(old_audit_workdir.clone()),
    );

    let mut cache = FormatCache::new_for_test_with_audit_formats(
        feed_dir.clone(),
        work_dir.clone(),
        false,
        formats,
        audit_formats,
    );

    cache.initialize_with_force(true).unwrap();

    assert!(cache.get("old-scan-format").is_none());
    assert!(cache.get_audit("old-audit-format").is_none());

    assert!(!work_dir.join("old-scan-format").exists());
    assert!(!work_dir.join("old-audit-format").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn initialize_with_force_false_keeps_existing_audit_formats_when_feed_is_empty() {
    let feed_dir = temp_test_dir("init-no-force-empty-audit-feed");
    let work_dir = temp_test_dir("init-no-force-empty-audit-work");

    let old_scan_workdir = work_dir.join("old-scan-format");
    let old_audit_workdir = work_dir.join("old-audit-format");

    fs::create_dir_all(&old_scan_workdir).unwrap();
    fs::create_dir_all(&old_audit_workdir).unwrap();

    let mut formats = HashMap::new();
    formats.insert(
        "old-scan-format".to_string(),
        test_report_format(old_scan_workdir.clone()),
    );

    let mut audit_formats = HashMap::new();
    audit_formats.insert(
        "old-audit-format".to_string(),
        test_report_format(old_audit_workdir.clone()),
    );

    let mut cache = FormatCache::new_for_test_with_audit_formats(
        feed_dir.clone(),
        work_dir.clone(),
        false,
        formats,
        audit_formats,
    );

    cache.initialize_with_force(false).unwrap();

    assert!(cache.get("old-scan-format").is_some());
    assert!(cache.get_audit("old-audit-format").is_some());

    assert!(work_dir.join("old-scan-format").exists());
    assert!(work_dir.join("old-audit-format").exists());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn new_for_test_initializes_empty_audit_formats() {
    let feed_dir = temp_test_dir("new-for-test-feed");
    let work_dir = temp_test_dir("new-for-test-work");

    let formats = HashMap::new();

    let cache = FormatCache::new_for_test(feed_dir.clone(), work_dir.clone(), false, formats);

    assert!(cache.list().is_empty());
    assert!(cache.list_audit().is_empty());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

#[test]
fn new_for_test_with_audit_formats_initializes_both_maps() {
    let feed_dir = temp_test_dir("new-for-test-audit-feed");
    let work_dir = temp_test_dir("new-for-test-audit-work");

    let scan_workdir = work_dir.join("scan-format");
    let audit_workdir = work_dir.join("audit-format");

    fs::create_dir_all(&scan_workdir).unwrap();
    fs::create_dir_all(&audit_workdir).unwrap();

    let mut formats = HashMap::new();
    formats.insert("scan-format".to_string(), test_report_format(scan_workdir));

    let mut audit_formats = HashMap::new();
    audit_formats.insert(
        "audit-format".to_string(),
        test_report_format(audit_workdir),
    );

    let cache = FormatCache::new_for_test_with_audit_formats(
        feed_dir.clone(),
        work_dir.clone(),
        false,
        formats,
        audit_formats,
    );

    assert!(cache.get("scan-format").is_some());
    assert!(cache.get_audit("audit-format").is_some());

    assert!(cache.get("audit-format").is_none());
    assert!(cache.get_audit("scan-format").is_none());

    let _ = fs::remove_dir_all(feed_dir);
    let _ = fs::remove_dir_all(work_dir);
}

fn assert_built_in_formats_registered(cache: &FormatCache, work_dir: &Path) {
    assert!(cache.get(BUILT_IN_TYPST_TECHNICAL_ID).is_some());
    assert!(cache.get(BUILT_IN_NATIVE_PDF_TECHNICAL_ID).is_some());

    assert!(work_dir.join(BUILT_IN_TYPST_TECHNICAL_ID).exists());
    assert!(work_dir.join(BUILT_IN_NATIVE_PDF_TECHNICAL_ID).exists());
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
    ReportFormat::feed(
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

fn assert_built_in_formats_not_registered(cache: &FormatCache, work_dir: &Path) {
    assert!(cache.get(BUILT_IN_TYPST_TECHNICAL_ID).is_none());
    assert!(cache.get(BUILT_IN_NATIVE_PDF_TECHNICAL_ID).is_none());

    assert!(!work_dir.join(BUILT_IN_TYPST_TECHNICAL_ID).exists());
    assert!(!work_dir.join(BUILT_IN_NATIVE_PDF_TECHNICAL_ID).exists());
}
