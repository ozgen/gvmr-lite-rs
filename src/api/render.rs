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
        dto::{
            render::RenderRequest, render_xml::RenderXmlRequest,
            report_json_converter::report_json_to_envelope,
        },
        error::ApiError,
    },
    app::state::AppState,
    auth::{context::AuthContext, scope::require_scope},
    domain::{
        report_format::{RendererBackend, ReportFormat},
        report_model::ReportEnvelope,
    },
    service::report_renderer::RenderResult,
    xml::report_validator::parse_report_xml,
};

#[utoipa::path(
    post,
    path = "/api/v1/render",
    tag = "render",
    request_body = RenderRequest,
    responses(
        (status = 200, description = "Rendered report"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Report format not found"),
        (status = 422, description = "Validation failed"),
        (status = 500, description = "Render failed")
    )
)]
pub async fn render(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(req): Json<RenderRequest>,
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

    let fmt = get_report_format(&state, &req.format_id).await?;

    log_report_format(&fmt);

    let result = match fmt.backend {
        RendererBackend::FeedPipeline => {
            let report_json = req.report_json_value();

            state
                .renderer
                .render(
                    &fmt,
                    &report_json,
                    &req.params,
                    req.timeout_seconds,
                    req.output_name.as_deref(),
                )
                .await
                .map_err(|err| ApiError::internal(format!("Render failed: {err}")))?
        }

        RendererBackend::Typst => {
            let report = report_json_to_envelope(&req.report_json);

            render_typst_report(state, fmt, report, req.output_name).await?
        }

        RendererBackend::NativePdf => {
            let report = report_json_to_envelope(&req.report_json);

            render_native_pdf_report(state, fmt, report, req.output_name).await?
        }
    };

    build_render_response(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/render/xml",
    tag = "render",
    request_body = RenderXmlRequest,
    responses(
        (status = 200, description = "Rendered XML report"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Report format not found"),
        (status = 422, description = "Validation failed"),
        (status = 500, description = "Render failed")
    )
)]
pub async fn render_xml(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(req): Json<RenderXmlRequest>,
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

    let fmt = get_report_format(&state, &req.format_id).await?;

    log_report_format(&fmt);

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

        RendererBackend::Typst => {
            let report = parse_report_xml(&req.report_xml).map_err(|err| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid_report_xml",
                    format!("Report XML does not match ReportEnvelope: {err}"),
                )
            })?;

            render_typst_report(state, fmt, report, req.output_name).await?
        }

        RendererBackend::NativePdf => {
            let report = parse_report_xml(&req.report_xml).map_err(|err| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid_report_xml",
                    format!("Report XML does not match ReportEnvelope: {err}"),
                )
            })?;

            render_native_pdf_report(state, fmt, report, req.output_name).await?
        }
    };

    build_render_response(result)
}

async fn get_report_format(state: &AppState, format_id: &str) -> Result<ReportFormat, ApiError> {
    let cache = state.format_cache.read().await;

    let Some(fmt) = cache.get(format_id) else {
        return Err(ApiError::not_found(
            "report_format_not_found",
            format!("Report format not found: {format_id}"),
        ));
    };

    Ok(fmt.clone())
}

fn log_report_format(fmt: &ReportFormat) {
    tracing::debug!(
        format_id = %fmt.id,
        format_name = %fmt.name,
        extension = %fmt.extension,
        content_type = %fmt.content_type,
        backend = ?fmt.backend,
        source = ?fmt.source,
        workdir = %fmt.workdir.display(),
        files_count = fmt.files.len(),
        "retrieved report format from cache"
    );
}

async fn render_native_pdf_report(
    state: AppState,
    fmt: ReportFormat,
    report: ReportEnvelope,
    output_name: Option<String>,
) -> Result<RenderResult, ApiError> {
    let renderer = state.native_pdf_renderer.clone();
    let filename = output_filename(output_name, &fmt, "native-technical-report");

    let content = task::spawn_blocking(move || renderer.render(&report))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "Native PDF render task failed");
            ApiError::internal(format!("Native PDF render task failed: {err}"))
        })?
        .map_err(|err| {
            tracing::error!(error = %err, "Native PDF render failed");
            ApiError::internal(format!("Native PDF render failed: {err}"))
        })?;

    Ok(RenderResult {
        content,
        content_type: fmt.content_type,
        filename,
    })
}

async fn render_typst_report(
    state: AppState,
    fmt: ReportFormat,
    report: ReportEnvelope,
    output_name: Option<String>,
) -> Result<RenderResult, ApiError> {
    let renderer = state.typst_report_renderer.clone();
    let filename = output_filename(output_name, &fmt, "technical-chunked-report");
    tracing::info!(
        filtered = ?report.report.result_count.as_ref().and_then(|c| c.filtered.as_deref()),
        full = ?report.report.result_count.as_ref().and_then(|c| c.full.as_deref()),
        parsed_results = report.report.results.as_ref().map(|r| r.result.len()).unwrap_or(0),
        "Typst report input"
    );

    let content = task::spawn_blocking(move || renderer.render(&report))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "Typst render task failed");
            ApiError::internal(format!("Typst render task failed: {err}"))
        })?
        .map_err(|err| {
            tracing::error!(error = %err, "Typst render failed");
            ApiError::internal(format!("Typst render failed: {err}"))
        })?;

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
#[path = "render_tests.rs"]
mod render_tests;
