use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    api::{
        dto::report_format::{
            ReportFormatListResponse, ReportFormatResponse, ReportFormatSyncResponse,
        },
        error::ApiError,
    },
    app::state::AppState,
    auth::{context::AuthContext, scope::require_scope},
};

#[utoipa::path(
    get,
    path = "/api/v1/delta-report-formats",
    tag = "delta-report-formats",
    responses(
        (status = 200, description = "List delta report formats", body = ReportFormatListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    )
)]
pub async fn get_delta_report_formats(
    State(state): State<AppState>,
    ctx: AuthContext,
) -> Result<Json<ReportFormatListResponse>, ApiError> {
    require_scope(
        &ctx,
        &state.settings.auth_mode,
        &state.settings.required_scope_sync,
    )?;

    let cache = state.format_cache.read().await;

    let mut items: Vec<ReportFormatResponse> = cache
        .list_delta()
        .values()
        .map(ReportFormatResponse::from)
        .collect();

    items.sort_by(|a, b| {
        let left = (&a.name, &a.id);
        let right = (&b.name, &b.id);
        left.cmp(&right)
    });

    Ok(Json(ReportFormatListResponse {
        count: items.len(),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/delta-report-formats/{format_id}",
    tag = "delta-report-formats",
    params(
        ("format_id" = String, Path, description = "Delta report format UUID")
    ),
    responses(
        (status = 200, description = "Delta report format", body = ReportFormatResponse),
        (status = 404, description = "Delta report format not found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    )
)]
pub async fn get_delta_report_format(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(format_id): Path<String>,
) -> Result<Json<ReportFormatResponse>, ApiError> {
    require_scope(
        &ctx,
        &state.settings.auth_mode,
        &state.settings.required_scope_sync,
    )?;

    let cache = state.format_cache.read().await;

    let Some(fmt) = cache.get_delta(&format_id) else {
        return Err(ApiError::not_found(
            "delta_report_format_not_found",
            format!("Delta report format not found: {format_id}"),
        ));
    };

    Ok(Json(ReportFormatResponse::from(fmt)))
}

#[utoipa::path(
    post,
    path = "/api/v1/delta-report-formats/sync",
    tag = "delta-report-formats",
    responses(
        (status = 200, description = "Sync delta report formats", body = ReportFormatSyncResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Sync failed")
    )
)]
pub async fn sync_delta_report_formats(
    State(state): State<AppState>,
    ctx: AuthContext,
) -> Result<Json<ReportFormatSyncResponse>, ApiError> {
    require_scope(
        &ctx,
        &state.settings.auth_mode,
        &state.settings.required_scope_sync,
    )?;

    let mut cache = state.format_cache.write().await;

    cache
        .rebuild()
        .map_err(|err| ApiError::internal(format!("Failed to sync delta report formats: {err}")))?;

    Ok(Json(ReportFormatSyncResponse {
        status: "ok",
        count: cache.list_delta().len(),
    }))
}

#[cfg(test)]
#[path = "delta_report_format_tests.rs"]
mod delta_report_format_tests;
