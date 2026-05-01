use std::sync::Arc;

use super::*;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use tokio::sync::RwLock;
use tower::util::ServiceExt;

use crate::{
    app::state::AppState,
    auth::context::AuthContext,
    config::settings::{AuthMode, Settings},
    service::format_cache::FormatCache,
};

async fn protected_handler(
    axum::extract::Extension(ctx): axum::extract::Extension<AuthContext>,
) -> impl IntoResponse {
    Json(json!({
        "subject": ctx.subject,
        "scopes": ctx.scopes,
    }))
}

fn test_settings(auth_mode: AuthMode) -> Settings {
    Settings {
        port: 8080,
        report_formats_feed_dir: "tests/feed".into(),
        work_dir: "tests/work".into(),
        rebuild_on_start: false,

        auth_mode,
        api_key: None,
        api_key_header: "x-api-key".to_string(),

        jwt_secret: None,
        jwt_audience: String::new(),
        jwt_issuer: String::new(),
        jwt_clock_skew_seconds: 0,

        required_scope_render: String::new(),
        required_scope_sync: String::new(),

        log_level: "debug".to_string(),
        max_body_bytes: 0,
        log_format: "".to_string(),
    }
}

fn test_app(settings: Settings) -> Router {
    let format_cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.work_dir.clone(),
        settings.rebuild_on_start,
    );

    let state = AppState {
        settings,
        format_cache: Arc::new(RwLock::new(format_cache)),
    };

    Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state)
}

#[tokio::test]
async fn require_auth_allows_request_when_auth_mode_is_none() {
    let app = test_app(test_settings(AuthMode::None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(value["subject"], serde_json::Value::Null);
    assert_eq!(value["scopes"], json!([]));
}

#[tokio::test]
async fn require_auth_returns_500_when_api_key_auth_is_enabled_but_key_is_missing() {
    let app = test_app(test_settings(AuthMode::ApiKey));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn require_auth_returns_401_when_api_key_is_missing() {
    let mut settings = test_settings(AuthMode::ApiKey);
    settings.api_key = Some("secret".to_string());

    let app = test_app(settings);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_auth_returns_401_when_api_key_is_wrong() {
    let mut settings = test_settings(AuthMode::ApiKey);
    settings.api_key = Some("secret".to_string());

    let app = test_app(settings);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("x-api-key", "wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_auth_allows_request_when_api_key_is_valid() {
    let mut settings = test_settings(AuthMode::ApiKey);
    settings.api_key = Some("secret".to_string());

    let app = test_app(settings);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("x-api-key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(value["subject"], "api_key");
}

#[tokio::test]
async fn require_auth_uses_custom_api_key_header() {
    let mut settings = test_settings(AuthMode::ApiKey);
    settings.api_key = Some("secret".to_string());
    settings.api_key_header = "x-custom-key".to_string();

    let app = test_app(settings);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("x-custom-key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn require_auth_returns_401_when_jwt_bearer_token_is_missing() {
    let mut settings = test_settings(AuthMode::Jwt);
    settings.jwt_secret = Some("secret".to_string());

    let app = test_app(settings);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_auth_returns_401_when_authorization_header_is_not_bearer() {
    let mut settings = test_settings(AuthMode::Jwt);
    settings.jwt_secret = Some("secret".to_string());

    let app = test_app(settings);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Basic abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
