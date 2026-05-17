use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TypstRenderError {
    #[error("failed to read Typst template '{path}': {source}")]
    ReadTemplate {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to create Typst work directory '{path}': {source}")]
    CreateWorkDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write Typst source '{path}': {source}")]
    WriteSource {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to run typst command: {0}")]
    RunTypst(std::io::Error),

    #[error("Typst compilation failed: {0}")]
    TypstFailed(String),

    #[error("failed to read generated PDF '{path}': {source}")]
    ReadPdf {
        path: PathBuf,
        source: std::io::Error,
    },
}
