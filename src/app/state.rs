use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    config::settings::Settings,
    service::{
        format_cache::FormatCache, json_report_renderer::JsonReportRenderer,
        report_renderer::ReportRenderer, xml_report_renderer::XmlReportRenderer,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub format_cache: Arc<RwLock<FormatCache>>,
    pub renderer: Arc<dyn ReportRenderer>,
    pub xml_renderer: XmlReportRenderer,
}

impl AppState {
    pub fn new(settings: Settings, format_cache: FormatCache) -> Self {
        Self {
            settings,
            format_cache: Arc::new(RwLock::new(format_cache)),
            renderer: Arc::new(JsonReportRenderer),
            xml_renderer: XmlReportRenderer,
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
            .finish()
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
