use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
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
    xml::report_format_parser::parse_report_format_xml,
};

#[derive(Debug, Clone)]
pub struct FormatCache {
    feed_dir: PathBuf,
    work_dir: PathBuf,
    rebuild_on_start: bool,
    formats: HashMap<String, ReportFormat>,
}

#[allow(dead_code)]
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

        let mut xml_files = Vec::new();

        if self.feed_dir.exists() {
            for entry in fs::read_dir(&self.feed_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().and_then(|ext| ext.to_str()) == Some("xml") {
                    xml_files.push(path);
                }
            }
        }

        xml_files.sort();

        if xml_files.is_empty() {
            warn!(
                feed_dir = %self.feed_dir.display(),
                "no XML report format files found"
            );

            if force {
                self.formats.clear();
                delete_stale_dirs(&self.work_dir, &HashSet::new())?;
            }

            return Ok(());
        }

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

        let wanted_ids: HashSet<String> = parsed_formats
            .iter()
            .map(|parsed| parsed.id.clone())
            .collect();

        if force {
            self.formats.clear();
            delete_stale_dirs(&self.work_dir, &wanted_ids)?;
        }

        for parsed in parsed_formats {
            if Self::should_skip_report_format(&parsed.id, &parsed.report_type) {
                tracing::info!(
                    format_id = %parsed.id,
                    name = %parsed.name,
                    report_type = %parsed.report_type,
                    "skipping report format"
                );
                continue;
            }

            let fmt_workdir = self.work_dir.join(&parsed.id);
            ensure_dir(&fmt_workdir)?;

            let keep_names: HashSet<String> =
                parsed.files.iter().map(|file| file.name.clone()).collect();

            if force {
                delete_stale_files(&fmt_workdir, &keep_names)?;
            }

            let mut files_out = Vec::new();

            for parsed_file in parsed.files {
                let out_path = fmt_workdir.join(&parsed_file.name);

                let should_write = force || self.rebuild_on_start || !out_path.exists();

                if let Some(content) = parsed_file.content {
                    if should_write {
                        write_bytes_atomic(&out_path, &content)?;
                        maybe_make_executable(&out_path, &content)?;
                    }

                    files_out.push(ReportFormatFile::new(parsed_file.name, out_path));
                    continue;
                }

                let src_path = self.feed_dir.join(&parsed_file.name);

                if should_write {
                    if !src_path.exists() {
                        warn!(
                            src_path = %src_path.display(),
                            format_id = %parsed.id,
                            "missing report format asset"
                        );
                        continue;
                    }

                    let data = fs::read(&src_path)?;
                    write_bytes_atomic(&out_path, &data)?;
                    maybe_make_executable(&out_path, &data)?;
                }

                files_out.push(ReportFormatFile::new(parsed_file.name, out_path));
            }

            debug!(
                format_id = %parsed.id,
                name = %parsed.name,
                files_count = files_out.len(),
                "cached report format"
            );

            self.formats.insert(
                parsed.id.clone(),
                ReportFormat::new(
                    parsed.id,
                    parsed.name,
                    parsed.extension,
                    parsed.content_type,
                    fmt_workdir,
                    files_out,
                ),
            );
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

    fn should_skip_report_format(format_id: &str, report_type: &str) -> bool {
        report_type.eq_ignore_ascii_case("audit")
            || DISCARDED_REPORT_FORMAT_IDS.contains(&format_id)
    }
}
