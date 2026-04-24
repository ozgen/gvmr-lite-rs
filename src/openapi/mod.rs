use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::health::live,
        crate::api::health::ready,
        crate::api::report_format::get_report_formats,
        crate::api::report_format::get_report_format,
        crate::api::report_format::sync_report_formats,
    ),
    components(
        schemas(
            crate::api::dto::health::LiveResponse,
            crate::api::dto::health::ReadyResponse,
            crate::api::dto::report_format::ReportFormatFileResponse,
            crate::api::dto::report_format::ReportFormatResponse,
            crate::api::dto::report_format::ReportFormatListResponse,
            crate::api::dto::report_format::ReportFormatSyncResponse,
        )
    ),
    tags(
        (name = "health", description = "Health endpoints"),
        (name = "report-formats", description = "Report format cache endpoints")
    )
)]
pub struct ApiDoc;
