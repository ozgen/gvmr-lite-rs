use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use tracing::{debug, warn};

use crate::{
    domain::{
        report_format::{ReportFormat, ReportFormatFile},
        report_format_constants::DISCARDED_REPORT_FORMAT_IDS,
    },
    infra::fs::{
        delete_stale_dirs, delete_stale_files, ensure_dir, maybe_make_executable,
        write_bytes_atomic,
    },
    xml::report_format_parser::{ParsedReportFormat, parse_report_format_xml},
};

#[derive(Debug, Clone)]
pub struct FormatCache {
    feed_dir: PathBuf,
    work_dir: PathBuf,
    rebuild_on_start: bool,
    formats: HashMap<String, ReportFormat>,
}

impl FormatCache {
    pub fn new(feed_dir: PathBuf, work_dir: PathBuf, rebuild_on_start: bool) -> Self {
        Self {
            feed_dir,
            work_dir,
            rebuild_on_start,
            formats: HashMap::new(),
        }
    }

    pub fn initialize(&mut self) -> std::io::Result<()> {
        self.initialize_with_force(false)
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
            .map(|parsed| parsed.id.clone())
            .collect();

        if force {
            self.formats.clear();
            delete_stale_dirs(&self.work_dir, &wanted_ids)?;
        }

        for parsed in parsed_formats {
            if let Some(format) = self.cache_format(parsed, force)? {
                self.formats.insert(format.id.clone(), format);
            }
        }

        Ok(())
    }

    pub fn rebuild(&mut self) -> std::io::Result<()> {
        self.initialize_with_force(true)
    }

    pub fn list(&self) -> &HashMap<String, ReportFormat> {
        &self.formats
    }

    pub fn get(&self, id: &str) -> Option<&ReportFormat> {
        self.formats.get(id)
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
            delete_stale_dirs(&self.work_dir, &HashSet::new())?;
        }

        Ok(())
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
        if Self::should_skip_report_format(&parsed.id, &parsed.report_type) {
            tracing::info!(
                format_id = %parsed.id,
                name = %parsed.name,
                report_type = %parsed.report_type,
                "skipping report format"
            );

            return Ok(None);
        }

        let fmt_workdir = self.work_dir.join(&parsed.id);
        ensure_dir(&fmt_workdir)?;

        let files_out = self.cache_format_files(&parsed, &fmt_workdir, force)?;

        debug!(
            format_id = %parsed.id,
            name = %parsed.name,
            files_count = files_out.len(),
            "cached report format"
        );

        Ok(Some(ReportFormat::new(
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
            if let Some(file_out) = self.cache_file(parsed_file, fmt_workdir, force, &parsed.id)? {
                files_out.push(file_out);
            }
        }

        Ok(files_out)
    }

    fn cache_file(
        &self,
        parsed_file: &crate::xml::report_format_parser::ParsedReportFormatFile,
        fmt_workdir: &Path,
        force: bool,
        format_id: &str,
    ) -> std::io::Result<Option<ReportFormatFile>> {
        let out_path = fmt_workdir.join(&parsed_file.name);
        let should_write = force || self.rebuild_on_start || !out_path.exists();

        if let Some(content) = &parsed_file.content {
            if should_write {
                write_bytes_atomic(&out_path, content)?;
                maybe_make_executable(&out_path, content)?;
            }

            return Ok(Some(ReportFormatFile::new(
                parsed_file.name.clone(),
                out_path,
            )));
        }

        let src_path = self.feed_dir.join(&parsed_file.name);

        if should_write {
            if !src_path.exists() {
                warn!(
                    src_path = %src_path.display(),
                    format_id = %format_id,
                    "missing report format asset"
                );

                return Ok(None);
            }

            let data = fs::read(&src_path)?;
            write_bytes_atomic(&out_path, &data)?;
            maybe_make_executable(&out_path, &data)?;
        }

        Ok(Some(ReportFormatFile::new(
            parsed_file.name.clone(),
            out_path,
        )))
    }

    fn should_skip_report_format(format_id: &str, report_type: &str) -> bool {
        report_type.eq_ignore_ascii_case("audit")
            || DISCARDED_REPORT_FORMAT_IDS.contains(&format_id)
    }
}

#[cfg(test)]
#[path = "format_cache_tests.rs"]
mod format_cache_tests;
