use axum::{
    Json,
    body::Body,
    extract::State,
    http::{
        HeaderValue, Response, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    },
};

use tokio::task;

use crate::{
    api::{
        dto::{render_audit::RenderAuditRequest, render_audit_xml::RenderAuditXmlRequest},
        error::ApiError,
    },
    app::state::AppState,
    auth::{context::AuthContext, scope::require_scope},
};

use gvmr_core::{
    domain::{
        report_format::{RendererBackend, ReportFormat},
        report_format_constants::BUILT_IN_NATIVE_PDF_COMPLIANCE_ID,
        report_model::ReportEnvelope,
    },
    service::audit::audit_report_json_xml_builder::build_audit_report_xml_from_json,
    service::report_renderer::RenderResult,
    xml::report_validator::parse_report_xml_flexible,
};

#[utoipa::path(
    post,
    path = "/api/v1/render/audit",
    tag = "render",
    request_body = RenderAuditRequest,
    responses(
        (status = 200, description = "Rendered audit report"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Audit report format not found"),
        (status = 422, description = "Validation failed"),
        (status = 500, description = "Render failed")
    )
)]
pub async fn render_audit(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(req): Json<RenderAuditRequest>,
) -> Result<Response<Body>, ApiError> {
    require_scope(
        &ctx,
        &state.settings.auth_mode,
        &state.settings.required_scope_render,
    )?;

    validate_audit_render_request(&req)?;

    let fmt = get_audit_report_format(&state, &req.format_id).await?;

    log_audit_report_format(&fmt);

    let report_json = req.report_json_value();

    let result = match fmt.backend {
        RendererBackend::FeedPipeline => state
            .audit_report_renderer
            .render_report_json(
                &fmt,
                &report_json,
                &req.params,
                req.timeout_seconds,
                req.output_name.as_deref(),
            )
            .await
            .map_err(|err| ApiError::internal(format!("Audit render failed: {err}")))?,

        RendererBackend::NativePdf if fmt.id == BUILT_IN_NATIVE_PDF_COMPLIANCE_ID => {
            let report_json = req.report_json_value();
            let report_xml = build_audit_report_xml_from_json(&report_json).map_err(|err| {
                ApiError::internal(format!("Audit report XML build failed: {err}"))
            })?;
            let report = parse_report_xml_flexible(&report_xml).map_err(|err| {
                ApiError::internal(format!("Audit report XML parse failed: {err}"))
            })?;
            render_native_compliance_report(state, fmt, report, req.output_name).await?
        }

        RendererBackend::Typst | RendererBackend::NativePdf => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_audit_renderer_backend",
                format!(
                    "Audit report rendering is currently only supported for feed pipeline formats, got backend: {:?}",
                    fmt.backend
                ),
            ));
        }
    };

    build_render_response(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/render/audit/xml",
    tag = "render",
    request_body = RenderAuditXmlRequest,
    responses(
        (status = 200, description = "Rendered audit report from XML"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Audit report format not found"),
        (status = 422, description = "Validation failed"),
        (status = 500, description = "Render failed")
    )
)]
pub async fn render_audit_xml(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(req): Json<RenderAuditXmlRequest>,
) -> Result<Response<Body>, ApiError> {
    require_scope(
        &ctx,
        &state.settings.auth_mode,
        &state.settings.required_scope_render,
    )?;

    req.validate().map_err(|message| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            message,
        )
    })?;

    let fmt = get_audit_report_format(&state, &req.format_id).await?;

    log_audit_report_format(&fmt);

    let result = match fmt.backend {
        RendererBackend::FeedPipeline => state
            .xml_renderer
            .render_report_xml(
                &fmt,
                &req.report_xml,
                &req.params,
                req.timeout_seconds,
                req.output_name.as_deref(),
            )
            .await
            .map_err(|err| ApiError::internal(format!("Render failed: {err}")))?,

        RendererBackend::NativePdf if fmt.id == BUILT_IN_NATIVE_PDF_COMPLIANCE_ID => {
            let report = parse_report_xml_flexible(&req.report_xml).map_err(|err| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid_report_xml",
                    format!("Report XML is not a valid report envelope or inner report: {err}"),
                )
            })?;

            render_native_compliance_report(state, fmt, report, req.output_name).await?
        }

        RendererBackend::Typst | RendererBackend::NativePdf => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_audit_renderer_backend",
                format!(
                    "Audit XML rendering is currently only supported for feed pipeline formats, got backend: {:?}",
                    fmt.backend
                ),
            ));
        }
    };

    build_render_response(result)
}

async fn render_native_compliance_report(
    state: AppState,
    fmt: ReportFormat,
    report: ReportEnvelope,
    output_name: Option<String>,
) -> Result<RenderResult, ApiError> {
    let renderer = state.native_pdf_renderer.clone();
    let is_delta_report = report.report.is_delta_report();
    let filename = output_filename(
        output_name,
        &fmt,
        if is_delta_report {
            "native-compliance-delta-report"
        } else {
            "native-compliance-report"
        },
    );

    let content = if is_delta_report {
        task::spawn_blocking(move || renderer.render_compliance_delta(&report))
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "Native compliance delta PDF render task failed");
                ApiError::internal(format!(
                    "Native compliance delta PDF render task failed: {err}"
                ))
            })?
            .map_err(|err| {
                tracing::error!(error = %err, "Native compliance delta PDF render failed");
                ApiError::internal(format!("Native compliance delta PDF render failed: {err}"))
            })?
    } else {
        task::spawn_blocking(move || renderer.render_compliance(&report))
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "Native compliance PDF render task failed");
                ApiError::internal(format!("Native compliance PDF render task failed: {err}"))
            })?
            .map_err(|err| {
                tracing::error!(error = %err, "Native compliance PDF render failed");
                ApiError::internal(format!("Native compliance PDF render failed: {err}"))
            })?
    };

    Ok(RenderResult {
        content,
        content_type: fmt.content_type,
        filename,
    })
}

fn output_filename(output_name: Option<String>, fmt: &ReportFormat, default_stem: &str) -> String {
    output_name.unwrap_or_else(|| {
        let extension = fmt.extension.trim();
        if extension.is_empty() {
            default_stem.to_string()
        } else {
            format!("{default_stem}.{extension}")
        }
    })
}

fn validate_audit_render_request(req: &RenderAuditRequest) -> Result<(), ApiError> {
    req.validate().map_err(|message| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            message,
        )
    })
}

async fn get_audit_report_format(
    state: &AppState,
    format_id: &str,
) -> Result<ReportFormat, ApiError> {
    let cache = state.format_cache.read().await;

    let Some(fmt) = cache.get_audit(format_id) else {
        return Err(ApiError::not_found(
            "audit_report_format_not_found",
            format!("Audit report format not found: {format_id}"),
        ));
    };

    Ok(fmt.clone())
}

fn log_audit_report_format(fmt: &ReportFormat) {
    tracing::debug!(
        format_id = %fmt.id,
        format_name = %fmt.name,
        extension = %fmt.extension,
        content_type = %fmt.content_type,
        backend = ?fmt.backend,
        source = ?fmt.source,
        workdir = %fmt.workdir.display(),
        files_count = fmt.files.len(),
        "retrieved audit report format from cache"
    );
}

fn build_render_response(result: RenderResult) -> Result<Response<Body>, ApiError> {
    let content_disposition = format!("attachment; filename=\"{}\"", result.filename);

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, result.content_type)
        .header(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&content_disposition).map_err(|err| {
                ApiError::internal(format!("Invalid content-disposition header: {err}"))
            })?,
        )
        .body(Body::from(result.content))
        .map_err(|err| ApiError::internal(format!("Failed to build response: {err}")))
}

#[cfg(test)]
#[path = "render_audit_tests.rs"]
mod render_audit_tests;
