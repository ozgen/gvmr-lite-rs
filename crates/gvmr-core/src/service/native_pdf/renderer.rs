use crate::domain::report_model::ReportEnvelope;

use super::{document::NativePdfDocument, error::NativePdfRenderError};

#[derive(Debug, Clone, Default)]
pub struct NativePdfRenderer;

impl NativePdfRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, report: &ReportEnvelope) -> Result<Vec<u8>, NativePdfRenderError> {
        self.render_technical(report)
    }

    pub fn render_technical(
        &self,
        report: &ReportEnvelope,
    ) -> Result<Vec<u8>, NativePdfRenderError> {
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

    /// Renders a delta report through the technical pipeline.
    ///
    /// `NativePdfDocument` detects delta reports and writes delta-specific cover,
    /// summary, result, and diff content while this shared pipeline renders the PDF.
    pub fn render_delta(&self, report: &ReportEnvelope) -> Result<Vec<u8>, NativePdfRenderError> {
        self.render_technical(report)
    }

    pub fn render_compliance(
        &self,
        report: &ReportEnvelope,
    ) -> Result<Vec<u8>, NativePdfRenderError> {
        let mut pass1 = NativePdfDocument::new(report);
        pass1.set_compliance_mode();
        pass1.prepare_toc(None);
        pass1.render_compliance_report();

        let toc_pages = pass1.toc_pages();
        let mut pass2 = NativePdfDocument::new(report);
        pass2.set_compliance_mode();
        pass2.prepare_toc(Some(&toc_pages));
        pass2.render_compliance_report();
        pass2.output()
    }

    /// Renders a compliance delta report through the compliance pipeline.
    ///
    /// `NativePdfDocument` detects delta reports and adds the baseline metadata,
    /// delta summary, result markers, and diffs while this shared pipeline renders the PDF.
    pub fn render_compliance_delta(
        &self,
        report: &ReportEnvelope,
    ) -> Result<Vec<u8>, NativePdfRenderError> {
        self.render_compliance(report)
    }
}

#[cfg(test)]
#[path = "renderer_tests.rs"]
mod renderer_tests;
