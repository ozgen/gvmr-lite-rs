use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::{
    domain::report_format::ReportFormat,
    service::json_report_renderer::{RenderError, RenderResult},
};

#[async_trait]
pub trait ReportRenderer: Send + Sync {
    async fn render(
        &self,
        fmt: &ReportFormat,
        report_json: &Value,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError>;
}
