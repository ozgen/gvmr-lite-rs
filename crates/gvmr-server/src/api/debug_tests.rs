use std::collections::HashSet;

use axum::{body::to_bytes, extract::State, http::StatusCode, response::IntoResponse};

use crate::{api::debug::sync_ping, app::state::AppState, auth::context::AuthContext};

use gvmr_core::service::format_cache::FormatCache;
use crate::config::settings::{AuthMode, Settings};

async fn response_body(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    String::from_utf8(bytes.to_vec()).unwrap()
}

fn test_settings(auth_mode: AuthMode, required_scope_sync: &str) -> Settings {
    Settings {
        port: 8084,
        report_formats_feed_dir: "/tmp/feed".into(),
        work_dir: "/tmp/work".into(),

        auth_mode,

        api_key: None,
        api_key_header: "X-API-Key".to_string(),

        jwt_secret: None,
        jwt_audience: "gvmr-lite".to_string(),
        jwt_issuer: "gvmd-lite".to_string(),
        jwt_clock_skew_seconds: 300,

        required_scope_render: "render".to_string(),
        required_scope_sync: required_scope_sync.to_string(),

        max_body_bytes: 50 * 1024 * 1024,

        rebuild_on_start: true,

        log_level: "info".to_string(),
        log_format: "pretty".to_string(),
        experimental_enabled: false,
    }
}

fn test_state(auth_mode: AuthMode, required_scope_sync: &str) -> AppState {
    let settings = test_settings(auth_mode, required_scope_sync);

    let format_cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        settings.experimental_enabled,
    );

    AppState::new(settings, format_cache)
}

#[tokio::test]
async fn sync_ping_returns_ok_when_required_scope_is_present() {
    let state = test_state(AuthMode::Jwt, "sync");

    let ctx = AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["sync".to_string()]),
        ..Default::default()
    };

    let response = sync_ping(State(state), ctx).await.unwrap().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "sync ok");
}

#[tokio::test]
async fn sync_ping_returns_forbidden_when_required_scope_is_missing() {
    let state = test_state(AuthMode::Jwt, "sync");

    let ctx = AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["render".to_string()]),
        ..Default::default()
    };

    let response = match sync_ping(State(state), ctx).await {
        Ok(_) => panic!("expected sync_ping to return forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sync_ping_returns_ok_when_auth_mode_is_none() {
    let state = test_state(AuthMode::None, "sync");

    let ctx = AuthContext::default();

    let response = sync_ping(State(state), ctx).await.unwrap().into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "sync ok");
}
