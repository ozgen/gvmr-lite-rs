use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NativePdfRenderError {
    #[error("failed to write native PDF to '{path}': {source}")]
    WritePdf {
        path: PathBuf,
        source: fpdf::FpdfError,
    },

    #[error("failed to read generated native PDF '{path}': {source}")]
    ReadPdf {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to remove native PDF temporary file '{path}': {source}")]
    Cleanup {
        path: PathBuf,
        source: std::io::Error,
    },
}
