use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    api::error::ApiError,
    app::state::AppState,
    auth::{bearer::extract_bearer, jwt::validate_jwt},
    config::settings::AuthMode,
};

pub async fn require_auth(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match state.settings.auth_mode {
        AuthMode::None => next.run(req).await,
        AuthMode::ApiKey => require_api_key(state, req, next).await,
        AuthMode::Jwt => require_jwt(state, req, next).await,
    }
}

async fn require_api_key(state: AppState, req: Request<axum::body::Body>, next: Next) -> Response {
    let Some(expected) = state.settings.api_key.as_deref() else {
        return ApiError::internal("API key auth enabled but GVMR_API_KEY is not set")
            .into_response();
    };

    let header_name = state.settings.api_key_header.as_str();

    let provided = req
        .headers()
        .get(header_name)
        .and_then(|value| value.to_str().ok());

    if provided != Some(expected) {
        return ApiError::unauthorized("Invalid API key").into_response();
    }

    next.run(req).await
}

async fn require_jwt(state: AppState, mut req: Request<axum::body::Body>, next: Next) -> Response {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| extract_bearer(Some(value)));

    let Some(token) = token else {
        return ApiError::unauthorized("Missing Bearer token").into_response();
    };

    let auth_context = match validate_jwt(&token, &state.settings) {
        Ok(ctx) => ctx,
        Err(err) => return err.into_response(),
    };

    req.extensions_mut().insert(auth_context);

    next.run(req).await
}
