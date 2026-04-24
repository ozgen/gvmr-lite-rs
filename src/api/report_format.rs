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

pub async fn get_report_formats(
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
        .list()
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

pub async fn get_report_format(
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

    let Some(fmt) = cache.get(&format_id) else {
        return Err(ApiError::not_found(
            "report_format_not_found",
            format!("Report format not found: {format_id}"),
        ));
    };

    Ok(Json(ReportFormatResponse::from(fmt)))
}

pub async fn sync_report_formats(
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
        .map_err(|err| ApiError::internal(format!("Failed to sync report formats: {err}")))?;
    Ok(Json(ReportFormatSyncResponse {
        status: "ok",
        count: cache.list().len(),
    }))
}
