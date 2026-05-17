use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    domain::report_model::ReportEnvelope,
    infra::fs::write_bytes_atomic,
    service::typst::{
        config::TypstProcessLimits, error::TypstRenderError, source_builder::TypstSourceBuilder,
    },
};

use super::workdir::create_typst_work_dir;

#[derive(Debug, Clone)]
pub struct TypstReportRenderer {
    source_builder: TypstSourceBuilder,
    process_limits: TypstProcessLimits,
}

impl TypstReportRenderer {
    pub fn new(template_path: impl Into<PathBuf>, process_limits: TypstProcessLimits) -> Self {
        Self {
            source_builder: TypstSourceBuilder::new(template_path),
            process_limits,
        }
    }

    pub fn technical_report() -> Self {
        Self::new(
            "templates/typst/technical.typ",
            TypstProcessLimits::default(),
        )
    }

    pub fn technical_report_without_limits() -> Self {
        Self::new(
            "templates/typst/technical.typ",
            TypstProcessLimits::disabled(),
        )
    }

    pub fn render(&self, report: &ReportEnvelope) -> Result<Vec<u8>, TypstRenderError> {
        let typst_source = self.source_builder.build_report_source(report)?;

        let work_dir = create_typst_work_dir()?;
        let render_result = self.render_in_work_dir(typst_source, &work_dir);

        let _ = fs::remove_dir_all(&work_dir);

        render_result
    }

    fn render_in_work_dir(
        &self,
        typst_source: String,
        work_dir: &Path,
    ) -> Result<Vec<u8>, TypstRenderError> {
        let typst_path = work_dir.join("report.typ");
        let pdf_path = work_dir.join("report.pdf");

        write_bytes_atomic(&typst_path, typst_source.as_bytes()).map_err(|source| {
            TypstRenderError::WriteSource {
                path: typst_path.clone(),
                source,
            }
        })?;

        self.compile_typst(&typst_path, &pdf_path)?;
        self.read_pdf(&pdf_path)
    }

    fn compile_typst(&self, typst_path: &Path, pdf_path: &Path) -> Result<(), TypstRenderError> {
        let output = if self.process_limits.enabled {
            self.run_limited_typst(typst_path, pdf_path)?
        } else {
            self.run_typst_directly(typst_path, pdf_path)?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            return Err(TypstRenderError::TypstFailed(format!("{stderr}\n{stdout}")));
        }

        Ok(())
    }

    fn run_typst_directly(
        &self,
        typst_path: &Path,
        pdf_path: &Path,
    ) -> Result<std::process::Output, TypstRenderError> {
        Command::new("typst")
            .arg("compile")
            .arg(typst_path)
            .arg(pdf_path)
            .output()
            .map_err(TypstRenderError::RunTypst)
    }

    fn run_limited_typst(
        &self,
        typst_path: &Path,
        pdf_path: &Path,
    ) -> Result<std::process::Output, TypstRenderError> {
        let mut command = Command::new("systemd-run");

        if self.process_limits.use_user_scope {
            command.arg("--user");
        }

        command
            .arg("--scope")
            .arg("-p")
            .arg(format!("MemoryMax={}", self.process_limits.memory_max))
            .arg("-p")
            .arg(format!("CPUQuota={}", self.process_limits.cpu_quota))
            .arg("-p")
            .arg(format!("TasksMax={}", self.process_limits.tasks_max))
            .arg("typst")
            .arg("compile")
            .arg(typst_path)
            .arg(pdf_path);

        command.output().map_err(TypstRenderError::RunTypst)
    }

    fn read_pdf(&self, pdf_path: &Path) -> Result<Vec<u8>, TypstRenderError> {
        fs::read(pdf_path).map_err(|source| TypstRenderError::ReadPdf {
            path: pdf_path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
#[path = "renderer_tests.rs"]
mod renderer_tests;
