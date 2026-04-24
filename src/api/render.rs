use axum::{
    Json,
    body::Body,
    extract::State,
    http::{
        HeaderValue, Response, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    },
};

use crate::{
    api::{dto::render::RenderRequest, error::ApiError},
    app::state::AppState,
    auth::{context::AuthContext, scope::require_scope},
    service::json_report_renderer::JsonReportRenderer,
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

    let cache = state.format_cache.read().await;

    let Some(fmt) = cache.get(&req.format_id) else {
        return Err(ApiError::not_found(
            "report_format_not_found",
            format!("Report format not found: {}", req.format_id),
        ));
    };

    let renderer = JsonReportRenderer;
    let result = renderer
        .render(
            fmt,
            &req.report_json_value(),
            &req.params,
            req.timeout_seconds,
            req.output_name.as_deref(),
        )
        .await
        .map_err(|err| ApiError::internal(format!("Render failed: {err}")))?;

    let content_disposition = format!("attachment; filename=\"{}\"", result.filename);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, result.content_type)
        .header(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&content_disposition).map_err(|err| {
                ApiError::internal(format!("Invalid content-disposition header: {err}"))
            })?,
        )
        .body(Body::from(result.content))
        .map_err(|err| ApiError::internal(format!("Failed to build response: {err}")))?;

    Ok(response)
}
