use axum::extract::DefaultBodyLimit;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    api::{debug, health, render, report_format},
    app::state::AppState,
    auth::middleware::require_auth,
    openapi::ApiDoc,
};

pub fn build_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready));

    let protected_routes = Router::new()
        .route("/api/v1/ping", get(|| async { "ok" }))
        .route("/api/v1/sync-ping", get(debug::sync_ping))
        .route(
            "/api/v1/report-formats",
            get(report_format::get_report_formats),
        )
        .route(
            "/api/v1/report-formats/{format_id}",
            get(report_format::get_report_format),
        )
        .route(
            "/api/v1/report-formats/sync",
            post(report_format::sync_report_formats),
        )
        .route("/api/v1/render", post(render::render))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state)
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024)) // todo move this env variable
        .layer(TraceLayer::new_for_http())
}
