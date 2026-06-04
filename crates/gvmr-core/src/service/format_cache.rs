use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use tracing::{debug, info, warn};

use crate::{
    domain::{
        report_format::{ReportFormat, ReportFormatFile},
        report_format_constants::{
            BUILT_IN_NATIVE_PDF_TECHNICAL_ID, BUILT_IN_TYPST_TECHNICAL_ID,
            DISCARDED_REPORT_FORMAT_IDS,
        },
    },
    infra::fs::{
        delete_stale_dirs, delete_stale_files, ensure_dir, maybe_make_executable,
        write_bytes_atomic,
    },
    xml::report_format_parser::{
        ParsedReportFormat, ParsedReportFormatFile, parse_report_format_xml,
    },
};

#[derive(Debug, Clone)]
pub struct FormatCache {
    feed_dir: PathBuf,
    work_dir: PathBuf,
    rebuild_on_start: bool,
    experimental: bool,
    formats: HashMap<String, ReportFormat>,
    audit_formats: HashMap<String, ReportFormat>,
}

impl FormatCache {
    pub fn new(
        feed_dir: PathBuf,
        work_dir: PathBuf,
        rebuild_on_start: bool,
        experimental: bool,
    ) -> Self {
        Self {
            feed_dir,
            work_dir,
            rebuild_on_start,
            experimental,
            formats: HashMap::new(),
            audit_formats: HashMap::new(),
        }
    }

    pub fn initialize(&mut self) -> std::io::Result<()> {
        self.initialize_with_force(self.rebuild_on_start)
    }

    pub fn rebuild(&mut self) -> std::io::Result<()> {
        self.initialize_with_force(true)
    }

    pub fn initialize_with_force(&mut self, force: bool) -> std::io::Result<()> {
        ensure_dir(&self.work_dir)?;

        let xml_files = self.discover_xml_files()?;

        if xml_files.is_empty() {
            self.handle_empty_feed(force)?;
            return Ok(());
        }

        let parsed_formats = self.parse_formats(xml_files);

        let wanted_ids: HashSet<String> = parsed_formats
            .iter()
            .filter(|parsed| !Self::should_skip_report_format(&parsed.id))
            .map(|parsed| parsed.id.clone())
            .collect();

        if force {
            self.formats.clear();
            self.audit_formats.clear();
            delete_stale_dirs(&self.work_dir, &wanted_ids)?;
        }

        for parsed in parsed_formats {
            if Self::should_skip_report_format(&parsed.id) {
                info!(
                    format_id = %parsed.id,
                    name = %parsed.name,
                    report_type = %parsed.report_type,
                    "skipping discarded report format"
                );

                continue;
            }

            let supports_audit = Self::supports_audit_report_format(&parsed.report_type);
            let supports_scan = Self::supports_scan_report_format(&parsed.report_type);

            let Some(format) = self.cache_format(parsed, force)? else {
                continue;
            };

            if supports_scan {
                debug!(
                    format_id = %format.id,
                    name = %format.name,
                    "registered report format"
                );

                self.formats.insert(format.id.clone(), format.clone());
            }

            if supports_audit {
                debug!(
                    format_id = %format.id,
                    name = %format.name,
                    "registered audit report format"
                );

                self.audit_formats.insert(format.id.clone(), format);
            }
        }

        self.register_built_in_formats()?;

        Ok(())
    }

    pub fn list(&self) -> &HashMap<String, ReportFormat> {
        &self.formats
    }

    pub fn get(&self, id: &str) -> Option<&ReportFormat> {
        self.formats.get(id)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.formats.contains_key(id)
    }

    pub fn list_audit(&self) -> &HashMap<String, ReportFormat> {
        &self.audit_formats
    }

    pub fn get_audit(&self, id: &str) -> Option<&ReportFormat> {
        self.audit_formats.get(id)
    }

    pub fn contains_audit(&self, id: &str) -> bool {
        self.audit_formats.contains_key(id)
    }

    fn supports_audit_report_format(report_type: &str) -> bool {
        let report_type = report_type.trim();

        report_type.eq_ignore_ascii_case("audit") || report_type.eq_ignore_ascii_case("all")
    }

    fn supports_scan_report_format(report_type: &str) -> bool {
        let report_type = report_type.trim();

        report_type.is_empty()
            || report_type.eq_ignore_ascii_case("scan")
            || report_type.eq_ignore_ascii_case("report")
            || report_type.eq_ignore_ascii_case("all")
    }

    fn register_built_in_formats(&mut self) -> std::io::Result<()> {
        if !self.experimental {
            return Ok(());
        }

        let typst_workdir = self.work_dir.join(BUILT_IN_TYPST_TECHNICAL_ID);
        ensure_dir(&typst_workdir)?;

        let typst_format = ReportFormat::built_in_typst(
            BUILT_IN_TYPST_TECHNICAL_ID,
            "Typst Technical Report",
            "pdf",
            "application/pdf",
            typst_workdir,
        );

        self.formats.insert(typst_format.id.clone(), typst_format);

        let native_pdf_workdir = self.work_dir.join(BUILT_IN_NATIVE_PDF_TECHNICAL_ID);
        ensure_dir(&native_pdf_workdir)?;

        let native_pdf_format = ReportFormat::built_in_native_pdf(
            BUILT_IN_NATIVE_PDF_TECHNICAL_ID,
            "Native PDF Technical Report",
            "pdf",
            "application/pdf",
            native_pdf_workdir,
        );

        self.formats
            .insert(native_pdf_format.id.clone(), native_pdf_format);

        Ok(())
    }

    fn discover_xml_files(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut xml_files = Vec::new();

        if !self.feed_dir.exists() {
            return Ok(xml_files);
        }

        for entry in fs::read_dir(&self.feed_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|ext| ext.to_str()) == Some("xml") {
                xml_files.push(path);
            }
        }

        xml_files.sort();

        Ok(xml_files)
    }

    fn handle_empty_feed(&mut self, force: bool) -> std::io::Result<()> {
        warn!(
            feed_dir = %self.feed_dir.display(),
            "no XML report format found"
        );

        if force {
            self.formats.clear();
            self.audit_formats.clear();
            delete_stale_dirs(&self.work_dir, &HashSet::new())?;
        }

        self.register_built_in_formats()
    }

    fn parse_formats(&self, xml_files: Vec<PathBuf>) -> Vec<ParsedReportFormat> {
        let mut parsed_formats = Vec::new();

        for xml_path in xml_files {
            match parse_report_format_xml(&xml_path) {
                Ok(parsed) => parsed_formats.push(parsed),
                Err(err) => {
                    warn!(
                        xml_path = %xml_path.display(),
                        error = %err,
                        "failed to parse report format XML"
                    );
                }
            }
        }

        parsed_formats
    }

    fn cache_format(
        &self,
        parsed: ParsedReportFormat,
        force: bool,
    ) -> std::io::Result<Option<ReportFormat>> {
        let fmt_workdir = self.work_dir.join(&parsed.id);
        ensure_dir(&fmt_workdir)?;

        let files_out = self.cache_format_files(&parsed, &fmt_workdir, force)?;

        debug!(
            format_id = %parsed.id,
            name = %parsed.name,
            report_type = %parsed.report_type,
            files_count = files_out.len(),
            "cached report format"
        );

        Ok(Some(ReportFormat::feed(
            parsed.id,
            parsed.name,
            parsed.extension,
            parsed.content_type,
            fmt_workdir,
            files_out,
        )))
    }

    fn cache_format_files(
        &self,
        parsed: &ParsedReportFormat,
        fmt_workdir: &Path,
        force: bool,
    ) -> std::io::Result<Vec<ReportFormatFile>> {
        let keep_names: HashSet<String> =
            parsed.files.iter().map(|file| file.name.clone()).collect();

        if force {
            delete_stale_files(fmt_workdir, &keep_names)?;
        }

        let mut files_out = Vec::new();

        for parsed_file in &parsed.files {
            let Some(file_out) = self.cache_file(parsed_file, fmt_workdir, force, &parsed.id)?
            else {
                continue;
            };

            files_out.push(file_out);
        }

        Ok(files_out)
    }

    fn cache_file(
        &self,
        parsed_file: &ParsedReportFormatFile,
        fmt_workdir: &Path,
        force: bool,
        format_id: &str,
    ) -> std::io::Result<Option<ReportFormatFile>> {
        let out_path = fmt_workdir.join(&parsed_file.name);
        let should_write = force || self.rebuild_on_start || !out_path.exists();

        if !should_write {
            return Ok(Some(ReportFormatFile {
                name: parsed_file.name.clone(),
                path: out_path,
            }));
        }

        if let Some(content) = parsed_file.content.as_deref() {
            write_bytes_atomic(&out_path, content)?;
            maybe_make_executable(&out_path, content)?;

            return Ok(Some(ReportFormatFile {
                name: parsed_file.name.clone(),
                path: out_path,
            }));
        }

        let src_path_with_format_id = self.feed_dir.join(format_id).join(&parsed_file.name);
        let src_path = if src_path_with_format_id.exists() {
            src_path_with_format_id
        } else {
            self.feed_dir.join(&parsed_file.name)
        };

        if !src_path.exists() {
            warn!(
                src_path = %src_path.display(),
                format_id = %format_id,
                file_name = %parsed_file.name,
                "missing report format asset"
            );

            return Ok(None);
        }

        let data = fs::read(&src_path)?;

        write_bytes_atomic(&out_path, &data)?;
        maybe_make_executable(&out_path, &data)?;

        Ok(Some(ReportFormatFile {
            name: parsed_file.name.clone(),
            path: out_path,
        }))
    }

    fn should_skip_report_format(format_id: &str) -> bool {
        DISCARDED_REPORT_FORMAT_IDS.contains(&format_id)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(
        feed_dir: PathBuf,
        work_dir: PathBuf,
        rebuild_on_start: bool,
        formats: HashMap<String, ReportFormat>,
    ) -> Self {
        Self {
            feed_dir,
            work_dir,
            rebuild_on_start,
            experimental: false,
            formats,
            audit_formats: HashMap::new(),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test_with_audit_formats(
        feed_dir: PathBuf,
        work_dir: PathBuf,
        rebuild_on_start: bool,
        formats: HashMap<String, ReportFormat>,
        audit_formats: HashMap<String, ReportFormat>,
    ) -> Self {
        Self {
            feed_dir,
            work_dir,
            rebuild_on_start,
            experimental: false,
            formats,
            audit_formats,
        }
    }
}

#[cfg(test)]
#[path = "format_cache_tests.rs"]
mod format_cache_tests;
