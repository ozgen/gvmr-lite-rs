use crate::domain::report_model::ReportEnvelope;

use super::{document::NativePdfDocument, error::NativePdfRenderError};

#[derive(Debug, Clone, Default)]
pub struct NativePdfRenderer;

impl NativePdfRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, report: &ReportEnvelope) -> Result<Vec<u8>, NativePdfRenderError> {
        let mut pass1 = NativePdfDocument::new(report);
        pass1.prepare_toc(None);
        pass1.write_cover();
        pass1.write_result_overview();
        pass1.write_results_per_host();

        let toc_pages = pass1.toc_pages();

        let mut pass2 = NativePdfDocument::new(report);
        pass2.prepare_toc(Some(&toc_pages));
        pass2.render()
    }
}

#[cfg(test)]
#[path = "renderer_tests.rs"]
mod renderer_tests;
