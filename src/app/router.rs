use axum::{Router, routing::get};

use crate::{api::health, app::state::AppState};

pub fn build_router() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
}
