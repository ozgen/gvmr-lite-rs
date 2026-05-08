use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RenderXmlRequest {
    pub format_id: String,
    pub report_xml: String,

    #[serde(default)]
    pub params: Map<String, Value>,

    pub output_name: Option<String>,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_timeout_seconds() -> u64 {
    300
}

impl RenderXmlRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout_seconds < 1 || self.timeout_seconds > 1201 {
            return Err("timeout_seconds must be between 1 and 1201".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "render_xml_tests.rs"]
mod render_xml_tests;
