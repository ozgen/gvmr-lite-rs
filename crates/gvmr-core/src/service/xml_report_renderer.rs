use serde_json::{Map, Value};
use tracing::info;

use crate::{
    domain::report_format::ReportFormat,
    service::{
        report_renderer::{RenderError, RenderResult},
        script_render_runner::render_report_xml_with_generate,
    },
    xml::report_validator::validate_report_xml_flexible,
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

        validate_report_xml_flexible(report_xml)
            .map_err(|err| RenderError::InvalidXml(err.to_string()))?;

        render_report_xml_with_generate(fmt, report_xml, params, timeout_seconds, output_name).await
    }
}

pub fn normalize_report_xml_for_feed_pipeline(report_xml: &str) -> Result<String, String> {
    // romxmltree is added for this normalization step, but we also have quick-xml in the dependencies.
    // We could consider using quick-xml instead to avoid adding another XML parsing dependency,
    // but roxmltree provides a convenient API for this kind of document manipulation so it's used for now.
    let document =
        roxmltree::Document::parse(report_xml).map_err(|err| format!("invalid XML: {err}"))?;

    let root = document.root_element();

    if root.tag_name().name() != "report" {
        return Err("invalid report XML: root element must be <report>".to_string());
    }

    let Some(inner_report) = root
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "report")
    else {
        return Ok(report_xml.to_string());
    };

    let range = inner_report.range();

    Ok(report_xml[range].to_string())
}

#[cfg(test)]
#[path = "xml_report_renderer_tests.rs"]
mod xml_report_renderer_tests;
