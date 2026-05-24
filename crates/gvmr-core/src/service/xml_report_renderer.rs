use serde_json::{Map, Value};
use tracing::info;

use crate::{
    domain::report_format::ReportFormat,
    service::{
        report_renderer::{RenderError, RenderResult},
        script_render_runner::render_report_xml_with_generate,
    },
    xml::report_validator::validate_report_xml,
};

#[derive(Debug, Clone, Default)]
pub struct XmlReportRenderer;

impl XmlReportRenderer {
    pub async fn render_report_xml(
        &self,
        fmt: &ReportFormat,
        report_xml: &str,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError> {
        info!(
            format_id = %fmt.id,
            format_name = %fmt.name,
            "validating raw report XML"
        );

        validate_report_xml(report_xml).map_err(|err| RenderError::InvalidXml(err.to_string()))?;

        render_report_xml_with_generate(fmt, report_xml, params, timeout_seconds, output_name).await
    }
}

#[cfg(test)]
#[path = "xml_report_renderer_tests.rs"]
mod xml_report_renderer_tests;
