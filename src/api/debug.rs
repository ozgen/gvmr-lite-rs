use axum::{extract::State, response::IntoResponse};

use crate::{
    api::error::ApiError,
    app::state::AppState,
    auth::{context::AuthContext, scope::require_scope},
};

pub async fn sync_ping(
    State(state): State<AppState>,
    ctx: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    require_scope(&ctx, &state.settings.required_scope_sync)?;

    Ok("sync ok")
}