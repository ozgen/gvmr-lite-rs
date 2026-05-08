use async_trait::async_trait;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::domain::report_format::ReportFormat;

#[derive(Debug, Error)]
pub enum RenderError {
    #[error("generate script not found for format {format_id}")]
    GenerateScriptNotFound { format_id: String },

    #[error("generate script not present in temporary workdir for format {format_id}")]
    GenerateScriptMissingInTempDir { format_id: String },

    #[error("failed to create render temp directory: {0}")]
    TempDir(std::io::Error),

    #[error("failed to write report.xml: {0}")]
    WriteReport(std::io::Error),

    #[error("failed to copy report format assets: {0}")]
    CopyAssets(std::io::Error),

    #[error("failed to run render command: {0}")]
    RunCommand(std::io::Error),

    #[error("failed to read render output file: {0}")]
    ReadOutput(std::io::Error),

    #[error("failed to build report XML: {0}")]
    BuildXml(String),

    #[error("invalid report XML: {0}")]
    InvalidXml(String),

    #[error(
        "render produced no output\nformat_id={format_id}\nreturncode={returncode}\nstderr={stderr}\ntmp_files={tmp_files:?}"
    )]
    NoOutput {
        format_id: String,
        returncode: i32,
        stderr: String,
        tmp_files: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct RenderResult {
    pub content: Vec<u8>,
    pub content_type: String,
    pub filename: String,
}

#[async_trait]
pub trait ReportRenderer: Send + Sync {
    async fn render(
        &self,
        fmt: &ReportFormat,
        report_json: &Value,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError>;
}
