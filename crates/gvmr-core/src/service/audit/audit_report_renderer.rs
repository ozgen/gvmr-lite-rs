use serde_json::{Map, Value};
use tracing::info;

use crate::domain::audit_report_model::AuditReportEnvelope;

use crate::{
    domain::report_format::ReportFormat,
    service::{
        audit::{
            audit_report_json_xml_builder::build_audit_report_xml_from_json,
            audit_report_xml_builder::build_audit_report_xml,
        },
        report_renderer::{RenderError, RenderResult},
        script_render_runner::render_report_xml_with_generate,
        xml_report_renderer::normalize_report_xml_for_feed_pipeline,
    },
};

#[derive(Debug, Clone, Default)]
pub struct AuditReportRenderer;

impl AuditReportRenderer {
    pub async fn render_report(
        &self,
        fmt: &ReportFormat,
        report: &AuditReportEnvelope,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError> {
        info!(
            format_id = %fmt.id,
            format_name = %fmt.name,
            "building audit report XML from audit model"
        );

        let envelope_xml = build_audit_report_xml(report)?;

        maybe_write_debug_xml("audit-report-envelope.xml", &envelope_xml);

        let feed_xml = normalize_report_xml_for_feed_pipeline(&envelope_xml)
            .map_err(RenderError::InvalidXml)?;

        maybe_write_debug_xml("audit-report-feed-input.xml", &feed_xml);

        render_report_xml_with_generate(fmt, &feed_xml, params, timeout_seconds, output_name).await
    }

    pub async fn render_report_json(
        &self,
        fmt: &ReportFormat,
        report_json: &Value,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError> {
        info!(
            format_id = %fmt.id,
            format_name = %fmt.name,
            "building audit report XML from audit JSON"
        );

        maybe_write_debug_json("audit-report-input.json", report_json);

        let feed_xml = build_audit_report_xml_from_json(report_json)?;

        maybe_write_debug_xml("audit-report-feed-input.xml", &feed_xml);

        render_report_xml_with_generate(fmt, &feed_xml, params, timeout_seconds, output_name).await
    }
}

fn maybe_write_debug_json(name: &str, value: &Value) {
    let Ok(debug_root) = std::env::var("GVMR_RENDER_DEBUG_DIR") else {
        return;
    };

    let path = std::path::PathBuf::from(debug_root).join(name);

    let _ = std::fs::write(
        path,
        serde_json::to_string_pretty(value).unwrap_or_default(),
    );
}

fn maybe_write_debug_xml(name: &str, value: &str) {
    let Ok(debug_root) = std::env::var("GVMR_RENDER_DEBUG_DIR") else {
        return;
    };

    let path = std::path::PathBuf::from(debug_root).join(name);

    let _ = std::fs::write(path, value);
}

#[cfg(test)]
#[path = "audit_report_renderer_tests.rs"]
mod audit_report_renderer_tests;
