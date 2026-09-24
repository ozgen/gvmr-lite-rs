use super::{get_delta_report_format, get_delta_report_formats, sync_delta_report_formats};

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use serde_json::{Map, Value};

use crate::{
    app::state::AppState,
    auth::context::AuthContext,
    config::settings::{AuthMode, Settings},
};

use gvmr_core::{
    domain::report_format::{ReportFormat, ReportFormatFile},
    service::{
        format_cache::FormatCache,
        report_renderer::{RenderError, RenderResult, ReportRenderer},
    },
};

#[derive(Debug)]
struct FakeRenderer;

#[async_trait]
impl ReportRenderer for FakeRenderer {
    async fn render(
        &self,
        _fmt: &ReportFormat,
        _report_json: &Value,
        _params: &Map<String, Value>,
        _timeout_seconds: u64,
        _output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError> {
        Ok(RenderResult {
            filename: "unused.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            content: Vec::new(),
        })
    }
}

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

fn test_state(
    auth_mode: AuthMode,
    required_scope_sync: &str,
    formats: Vec<ReportFormat>,
    audit_formats: Vec<ReportFormat>,
    delta_formats: Vec<ReportFormat>,
) -> AppState {
    let feed_dir = temp_test_dir("delta-format-feed");
    let work_dir = temp_test_dir("delta-format-work");
    let settings = test_settings(auth_mode, required_scope_sync, feed_dir.clone(), work_dir);

    let to_map = |formats: Vec<ReportFormat>| {
        formats
            .into_iter()
            .map(|format| (format.id.clone(), format))
            .collect::<HashMap<_, _>>()
    };

    let format_cache = FormatCache::new_for_test_with_report_types(
        feed_dir,
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        to_map(formats),
        to_map(audit_formats),
        to_map(delta_formats),
    );

    AppState::new_for_test(settings, format_cache, Arc::new(FakeRenderer))
}

fn report_format(id: &str, name: &str) -> ReportFormat {
    let workdir = temp_test_dir(&format!("delta-format-{id}"));
    let generate_path = workdir.join("generate");
    fs::write(&generate_path, b"#!/bin/sh\nprintf 'unused'").unwrap();

    ReportFormat::feed(
        id.to_string(),
        name.to_string(),
        "pdf".to_string(),
        "application/pdf".to_string(),
        workdir.clone(),
        vec![ReportFormatFile::new("generate".to_string(), generate_path)],
    )
}

fn temp_test_dir(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let dir = std::env::temp_dir().join(format!(
        "gvmr-lite-rs-{name}-{}-{unique}",
        std::process::id()
    ));

    fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn get_delta_report_formats_returns_sorted_delta_formats() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![report_format("scan", "Scan")],
        vec![report_format("audit", "Audit")],
        vec![
            report_format("format-b", "Beta"),
            report_format("format-c", "Alpha"),
            report_format("format-a", "Alpha"),
            report_format("all", "All"),
        ],
    );

    let Json(response) = get_delta_report_formats(State(state), auth_context_with_sync_scope())
        .await
        .unwrap();

    assert_eq!(response.count, 4);
    assert_eq!(response.items[0].id, "all");
    assert_eq!(response.items[1].id, "format-a");
    assert_eq!(response.items[2].id, "format-c");
    assert_eq!(response.items[3].id, "format-b");
}

#[tokio::test]
async fn get_delta_report_format_returns_matching_format() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![],
        vec![],
        vec![report_format("format-1", "Delta PDF")],
    );

    let Json(response) = get_delta_report_format(
        State(state),
        auth_context_with_sync_scope(),
        Path("format-1".to_string()),
    )
    .await
    .unwrap();

    assert_eq!(response.id, "format-1");
    assert_eq!(response.name, "Delta PDF");
}

#[tokio::test]
async fn get_delta_report_format_returns_delta_not_found_error() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![],
        vec![],
        vec![report_format("format-1", "Delta PDF")],
    );

    let response = match get_delta_report_format(
        State(state),
        auth_context_with_sync_scope(),
        Path("missing".to_string()),
    )
    .await
    {
        Ok(_) => panic!("expected not found error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "delta_report_format_not_found");
}

#[tokio::test]
async fn delta_handlers_use_sync_scope() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![],
        vec![],
        vec![report_format("format-1", "Delta PDF")],
    );

    let response =
        match get_delta_report_formats(State(state), auth_context_without_sync_scope()).await {
            Ok(_) => panic!("expected forbidden error"),
            Err(error) => error.into_response(),
        };

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delta_handlers_allow_auth_mode_none() {
    let state = test_state(
        AuthMode::None,
        "sync",
        vec![],
        vec![],
        vec![report_format("format-1", "Delta PDF")],
    );

    let Json(response) = get_delta_report_formats(State(state), AuthContext::default())
        .await
        .unwrap();

    assert_eq!(response.count, 1);
}

#[tokio::test]
async fn sync_delta_report_formats_returns_ok_and_delta_count() {
    let state = test_state(
        AuthMode::Jwt,
        "sync",
        vec![],
        vec![],
        vec![
            report_format("format-1", "Delta PDF"),
            report_format("format-2", "Delta XML"),
        ],
    );

    let Json(response) = sync_delta_report_formats(State(state), auth_context_with_sync_scope())
        .await
        .unwrap();

    assert_eq!(response.status, "ok");
    assert_eq!(response.count, 0);
}
