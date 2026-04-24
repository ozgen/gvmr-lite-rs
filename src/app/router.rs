use axum::{Router, middleware, routing::get};
use tower_http::trace::TraceLayer;

use crate::{
    api::{debug, health},
    app::state::AppState,
    auth::middleware::require_auth,
};

pub fn build_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready));

    let protected_routes = Router::new()
        .route("/api/v1/ping", get(|| async { "ok" }))
        .route("/api/v1/sync-ping", get(debug::sync_ping))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
