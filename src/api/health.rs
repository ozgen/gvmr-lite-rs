use axum::{Json, extract::State};

use crate::{
    api::dto::health::{LiveResponse, ReadyResponse},
    app::state::AppState,
};

#[utoipa::path(
    get,
    path = "/health/live",
    responses(
        (status = 200, description = "Liveness probe", body = LiveResponse)
    )
)]
pub async fn live() -> Json<LiveResponse> {
    Json(LiveResponse::ok())
}

#[utoipa::path(
    get,
    path = "/health/ready",
    responses(
        (status = 200, description = "Readiness probe", body = ReadyResponse)
    )
)]
pub async fn ready(State(state): State<AppState>) -> Json<ReadyResponse> {
    let feed_dir = state.settings.report_formats_feed_dir.clone();
    let work_dir = state.settings.report_formats_work_dir();

    let feed_exists = feed_dir.exists();
    let work_exists = work_dir.exists();

    let formats_count = state.format_cache.read().await.list().len();

    Json(ReadyResponse::from_health_state(
        feed_dir,
        work_dir,
        feed_exists,
        work_exists,
        formats_count,
    ))
}
