use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::health::live,
        crate::api::health::ready,
        crate::api::report_format::get_report_formats,
        crate::api::report_format::get_report_format,
        crate::api::report_format::sync_report_formats,
        crate::api::audit_report_formats::sync_audit_report_formats,
        crate::api::audit_report_formats::get_audit_report_formats,
        crate::api::audit_report_formats::get_audit_report_format,
        crate::api::render::render,
        crate::api::render::render_xml,
        crate::api::render_audit::render_audit,
        crate::api::render_audit::render_audit_xml,
    ),
    components(
        schemas(
            crate::api::dto::health::LiveResponse,
            crate::api::dto::health::ReadyResponse,
            crate::api::dto::report_format::ReportFormatFileResponse,
            crate::api::dto::report_format::ReportFormatResponse,
            crate::api::dto::report_format::ReportFormatListResponse,
            crate::api::dto::report_format::ReportFormatSyncResponse,
            crate::api::dto::render::RenderRequest,
            crate::api::dto::render_xml::RenderXmlRequest,
            crate::api::dto::render_audit::RenderAuditRequest,
            crate::api::dto::render_audit_xml::RenderAuditXmlRequest,
        )
    ),
    tags(
        (name = "health", description = "Health endpoints"),
        (name = "report-formats", description = "Report format cache endpoints"),
        (name = "audit-report-formats", description = "Audit report format cache endpoints"), 
        (name = "render", description = "Report rendering endpoints"),
    )
)]
pub struct ApiDoc;

#[cfg(test)]
#[test]
fn openapi_document_can_be_generated() {
    let doc = ApiDoc::openapi();

    assert_eq!(doc.info.title, env!("CARGO_PKG_NAME"));
}
