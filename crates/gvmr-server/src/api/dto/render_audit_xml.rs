use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RenderAuditXmlRequest {
    pub format_id: String,
    pub report_xml: String,

    #[serde(default)]
    pub params: Map<String, Value>,

    pub output_name: Option<String>,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl RenderAuditXmlRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_id.trim().is_empty() {
            return Err("format_id must not be empty".to_string());
        }

        if self.report_xml.trim().is_empty() {
            return Err("report_xml must not be empty".to_string());
        }

        if self.timeout_seconds < 1 || self.timeout_seconds > 40001 {
            return Err("timeout_seconds must be between 1 and 40001".to_string());
        }

        Ok(())
    }
}

fn default_timeout_seconds() -> u64 {
    300
}

#[cfg(test)]
#[path = "render_audit_xml_tests.rs"]
mod render_audit_xml_tests;
