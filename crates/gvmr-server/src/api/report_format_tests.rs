use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{
    api::report_format::{get_report_format, get_report_formats, sync_report_formats},
    app::state::AppState,
    auth::context::AuthContext,
};

use gvmr_core::{
    config::settings::{AuthMode, Settings},
    domain::report_format::{ReportFormat, ReportFormatFile},
    service::format_cache::FormatCache,
};

fn test_settings(
    auth_mode: AuthMode,
    required_scope_sync: &str,
    feed_dir: PathBuf,
    work_dir: PathBuf,
) -> Settings {
    Settings {
        port: 8084,
        report_formats_feed_dir: feed_dir,
        work_dir,

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

fn auth_context_with_sync_scope() -> AuthContext {
    AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["sync".to_string()]),
        ..Default::default()
    }
}

fn auth_context_without_sync_scope() -> AuthContext {
    AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["render".to_string()]),
        ..Default::default()
    }
}

fn report_format(id: &str, name: &str, extension: &str, content_type: &str) -> ReportFormat {
    let workdir = PathBuf::from(format!("/tmp/work/report-formats/{id}"));

    ReportFormat::feed(
        id.to_string(),
        name.to_string(),
        extension.to_string(),
        content_type.to_string(),
        workdir.clone(),
        vec![ReportFormatFile::new(
            "report.xsl".to_string(),
            workdir.join("report.xsl"),
        )],
    )
}

fn test_state(
    auth_mode: AuthMode,
    required_scope_sync: &str,
    formats: Vec<ReportFormat>,
) -> AppState {
    let feed_dir = PathBuf::from("/tmp/feed");
    let work_dir = PathBuf::from("/tmp/work");

    let settings = test_settings(
        auth_mode,
        required_scope_sync,
        feed_dir.clone(),
        work_dir.clone(),
    );

    let formats = formats
        .into_iter()
        .map(|format| (format.id.clone(), format))
        .collect::<HashMap<_, _>>();

    let format_cache = FormatCache::new_for_test(
        feed_dir,
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        formats,
    );

    AppState::new(settings, format_cache)
}

#[tokio::test]
async fn get_report_formats_returns_sorted_items() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![
            report_format("format-2", "Zulu Report", "xml", "application/xml"),
            report_format("format-1", "Alpha Report", "pdf", "application/pdf"),
        ],
    );

    let Json(response) = get_report_formats(State(state), auth_context_with_sync_scope())
        .await
        .unwrap();

    assert_eq!(response.count, 2);

    assert_eq!(response.items[0].id, "format-1");
    assert_eq!(response.items[0].name, "Alpha Report");
    assert_eq!(response.items[0].extension, "pdf");
    assert_eq!(response.items[0].content_type, "application/pdf");
    assert_eq!(response.items[0].files.len(), 1);

    assert_eq!(response.items[1].id, "format-2");
    assert_eq!(response.items[1].name, "Zulu Report");
}

#[tokio::test]
async fn get_report_formats_returns_forbidden_when_scope_is_missing() {
    let state = test_state(AuthMode::Jwt, "sync", vec![]);

    let response = match get_report_formats(State(state), auth_context_without_sync_scope()).await {
        Ok(_) => panic!("expected forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_report_format_returns_matching_format() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![report_format(
            "format-1",
            "PDF Report",
            "pdf",
            "application/pdf",
        )],
    );

    let Json(response) = get_report_format(
        State(state),
        auth_context_with_sync_scope(),
        Path("format-1".to_string()),
    )
    .await
    .unwrap();

    assert_eq!(response.id, "format-1");
    assert_eq!(response.name, "PDF Report");
    assert_eq!(response.extension, "pdf");
    assert_eq!(response.content_type, "application/pdf");
    assert_eq!(response.files.len(), 1);
    assert_eq!(response.files[0].name, "report.xsl");
}

#[tokio::test]
async fn get_report_format_returns_not_found_when_format_is_missing() {
    let state = test_state(AuthMode::Jwt, "sync", vec![]);

    let response = match get_report_format(
        State(state),
        auth_context_with_sync_scope(),
        Path("missing-format".to_string()),
    )
    .await
    {
        Ok(_) => panic!("expected not found error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_report_format_returns_forbidden_when_scope_is_missing() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![report_format(
            "format-1",
            "PDF Report",
            "pdf",
            "application/pdf",
        )],
    );

    let response = match get_report_format(
        State(state),
        auth_context_without_sync_scope(),
        Path("format-1".to_string()),
    )
    .await
    {
        Ok(_) => panic!("expected forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sync_report_formats_returns_ok_for_empty_feed_dir() {
    let state = test_state(AuthMode::Jwt, "sync", vec![]);

    let Json(response) = sync_report_formats(State(state), auth_context_with_sync_scope())
        .await
        .unwrap();

    assert_eq!(response.status, "ok");
    assert_eq!(response.count, 0);
}

#[tokio::test]
async fn sync_report_formats_returns_forbidden_when_scope_is_missing() {
    let state = test_state(AuthMode::Jwt, "sync", vec![]);

    let response = match sync_report_formats(State(state), auth_context_without_sync_scope()).await
    {
        Ok(_) => panic!("expected forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn report_format_handlers_allow_access_when_auth_mode_is_none() {
    let state = test_state(
        AuthMode::None,
        "sync",
        vec![report_format(
            "format-1",
            "PDF Report",
            "pdf",
            "application/pdf",
        )],
    );

    let Json(response) = get_report_formats(State(state), AuthContext::default())
        .await
        .unwrap();

    assert_eq!(response.count, 1);
    assert_eq!(response.items[0].id, "format-1");
}
