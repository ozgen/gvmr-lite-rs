use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tokio::sync::RwLock;
use tower::ServiceExt;

use crate::{
    app::{router::build_router, state::AppState},
    config::settings::{AuthMode, Settings},
    service::format_cache::FormatCache,
};

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
        max_body_bytes: 1024,
        log_format: "pretty".to_string(),
    }
}

fn test_state(auth_mode: AuthMode) -> AppState {
    let settings = test_settings(auth_mode);

    let format_cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.work_dir.clone(),
        settings.rebuild_on_start,
    );

    AppState {
        settings,
        format_cache: Arc::new(RwLock::new(format_cache)),
    }
}

#[tokio::test]
async fn health_live_is_public() {
    let app = build_router(test_state(AuthMode::ApiKey));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn docs_are_public() {
    let app = build_router(test_state(AuthMode::ApiKey));

    let response = app
        .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert!(response.status().is_success() || response.status().is_redirection());
}

#[tokio::test]
async fn protected_route_requires_auth() {
    let mut state = test_state(AuthMode::ApiKey);
    state.settings.api_key = Some("secret".to_string());

    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_route_allows_valid_api_key() {
    let mut state = test_state(AuthMode::ApiKey);
    state.settings.api_key = Some("secret".to_string());

    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/ping")
                .header("x-api-key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    assert_eq!(&body[..], b"ok");
}
