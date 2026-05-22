use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use fpdf::Pdf;

use super::{document::NativePdfDocument, error::NativePdfRenderError};

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
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    let pid = std::process::id();

    std::env::temp_dir().join(format!("gvmr-lite-rs-native-pdf-{pid}-{millis}.pdf"))
}
