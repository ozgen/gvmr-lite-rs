use crate::domain::audit_report_model::AuditReportEnvelope;

use crate::service::report_renderer::RenderError;

pub fn build_audit_report_xml(report: &AuditReportEnvelope) -> Result<String, RenderError> {
    quick_xml::se::to_string(report).map_err(|err| RenderError::BuildXml(err.to_string()))
}

#[cfg(test)]
#[path = "audit_report_xml_builder_tests.rs"]
mod audit_report_xml_builder_tests;
