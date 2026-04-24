use std::{collections::HashMap, path::PathBuf};

use crate::domain::report_format::ReportFormat;

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
        std::fs::create_dir_all(&self.work_dir)?;

        if self.rebuild_on_start {
            self.rebuild()?;
        }

        Ok(())
    }

    pub fn rebuild(&mut self) -> std::io::Result<()> {
        self.formats.clear();

        if !self.feed_dir.exists() {
            return Ok(());
        }

        // Real XML parsing and materialization comes next.
        Ok(())
    }

    pub fn list(&self) -> &HashMap<String, ReportFormat> {
        &self.formats
    }

    pub fn get(&self, id: &str) -> Option<&ReportFormat> {
        self.formats.get(id)
    }
}
