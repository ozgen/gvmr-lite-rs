use async_trait::async_trait;
use serde_json::{Map, Value};
use tracing::info;

use crate::{
    domain::report_format::ReportFormat,
    service::{
        report_json_injector::inject_graph_gen_fields,
        report_renderer::{RenderError, RenderResult, ReportRenderer},
        report_xml_builder::build_report_xml,
        script_render_runner::render_report_xml_with_generate,
    },
};

#[derive(Debug, Clone, Default)]
pub struct JsonReportRenderer;

impl JsonReportRenderer {
    pub async fn render_report(
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
            "building report XML from JSON"
        );

        let injected = inject_graph_gen_fields(report_json).map_err(RenderError::BuildXml)?;
        maybe_write_debug_json("injected-report.json", &injected);

        let report_payload = injected.get("report").unwrap_or(&injected);

        let report_xml = build_report_xml(&serde_json::json!({ "report": report_payload }))
            .map_err(|err| RenderError::BuildXml(err.to_string()))?;

        render_report_xml_with_generate(fmt, &report_xml, params, timeout_seconds, output_name)
            .await
    }
}

#[async_trait]
impl ReportRenderer for JsonReportRenderer {
    async fn render(
        &self,
        fmt: &ReportFormat,
        report_json: &Value,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError> {
        self.render_report(fmt, report_json, params, timeout_seconds, output_name)
            .await
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

#[cfg(test)]
#[path = "json_report_renderer_tests.rs"]
mod json_report_renderer_tests;
