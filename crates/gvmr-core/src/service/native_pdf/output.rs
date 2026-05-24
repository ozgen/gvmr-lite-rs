use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use fpdf::Pdf;

use super::{document::NativePdfDocument, error::NativePdfRenderError};

static NATIVE_PDF_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn output(&mut self) -> Result<Vec<u8>, NativePdfRenderError> {
        let path = native_pdf_temp_path();

        self.pdf
            .output_file_and_close(path.to_string_lossy().as_ref())
            .map_err(|source| NativePdfRenderError::WritePdf {
                path: path.clone(),
                source,
            })?;

        let bytes = fs::read(&path).map_err(|source| NativePdfRenderError::ReadPdf {
            path: path.clone(),
            source,
        })?;

        if let Err(source) = fs::remove_file(&path) {
            return Err(NativePdfRenderError::Cleanup { path, source });
        }

        Ok(bytes)
    }
}

fn native_pdf_temp_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    let pid = std::process::id();
    let sequence = NATIVE_PDF_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!(
        "gvmr-lite-rs-native-pdf-{pid}-{nanos}-{sequence}.pdf"
    ))
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod output_tests;
