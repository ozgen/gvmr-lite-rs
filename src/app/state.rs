use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    config::settings::Settings,
    service::{
        format_cache::FormatCache, json_report_renderer::JsonReportRenderer,
        native_pdf::NativePdfRenderer, report_renderer::ReportRenderer,
        typst::renderer::TypstReportRenderer, xml_report_renderer::XmlReportRenderer,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub format_cache: Arc<RwLock<FormatCache>>,
    pub renderer: Arc<dyn ReportRenderer>,
    pub native_pdf_renderer: NativePdfRenderer,
    pub xml_renderer: XmlReportRenderer,
    pub typst_report_renderer: TypstReportRenderer,
}

impl AppState {
    pub fn new(settings: Settings, format_cache: FormatCache) -> Self {
        Self {
            settings,
            format_cache: Arc::new(RwLock::new(format_cache)),
            renderer: Arc::new(JsonReportRenderer),
            xml_renderer: XmlReportRenderer,
            native_pdf_renderer: NativePdfRenderer::new(),
            typst_report_renderer: TypstReportRenderer::technical_report(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(
        settings: Settings,
        format_cache: FormatCache,
        renderer: Arc<dyn ReportRenderer>,
    ) -> Self {
        Self {
            settings,
            format_cache: Arc::new(RwLock::new(format_cache)),
            renderer,
            xml_renderer: XmlReportRenderer,
            native_pdf_renderer: NativePdfRenderer::new(),
            typst_report_renderer: TypstReportRenderer::technical_report(),
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("settings", &self.settings)
            .field("format_cache", &self.format_cache)
            .field("renderer", &"<dyn ReportRenderer>")
            .field("xml_renderer", &"<XmlReportRenderer>")
            .field("native_pdf_renderer", &"<NativePdfRenderer>")
            .field("typst_report_renderer", &"<TypstReportRenderer>")
            .finish()
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
