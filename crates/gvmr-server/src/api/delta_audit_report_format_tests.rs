use super::{
    get_delta_audit_report_format, get_delta_audit_report_formats, sync_delta_audit_report_formats,
};

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

fn settings(feed_dir: PathBuf, work_dir: PathBuf) -> Settings {
    Settings {
        port: 8084,
        report_formats_feed_dir: feed_dir,
        work_dir,
        auth_mode: AuthMode::Jwt,
        api_key: None,
        api_key_header: "X-API-Key".to_string(),
        jwt_secret: None,
        jwt_audience: "gvmr-lite".to_string(),
        jwt_issuer: "gvmd-lite".to_string(),
        jwt_clock_skew_seconds: 300,
        required_scope_render: "render".to_string(),
        required_scope_sync: "sync".to_string(),
        max_body_bytes: 50 * 1024 * 1024,
        rebuild_on_start: true,
        log_level: "info".to_string(),
        log_format: "pretty".to_string(),
        experimental_enabled: false,
    }
}

fn sync_context() -> AuthContext {
    AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["sync".to_string()]),
        ..Default::default()
    }
}

fn test_state(
    formats: Vec<ReportFormat>,
    audit_formats: Vec<ReportFormat>,
    delta_formats: Vec<ReportFormat>,
    delta_audit_formats: Vec<ReportFormat>,
) -> AppState {
    let feed_dir = temp_test_dir("delta-audit-format-feed");
    let work_dir = temp_test_dir("delta-audit-format-work");
    let settings = settings(feed_dir.clone(), work_dir);
    let to_map = |items: Vec<ReportFormat>| {
        items
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect::<HashMap<_, _>>()
    };

    let cache = FormatCache::new_for_test_with_all_formats(
        feed_dir,
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        to_map(formats),
        to_map(audit_formats),
        to_map(delta_formats),
        to_map(delta_audit_formats),
    );

    AppState::new_for_test(settings, cache, Arc::new(FakeRenderer))
}

fn report_format(id: &str, name: &str) -> ReportFormat {
    let workdir = temp_test_dir(&format!("delta-audit-format-{id}"));
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
async fn get_delta_audit_report_formats_returns_sorted_audit_delta_formats() {
    let state = test_state(
        vec![report_format("technical", "Technical")],
        vec![report_format("audit", "Audit")],
        vec![report_format("delta", "Delta")],
        vec![
            report_format("format-b", "Beta"),
            report_format("format-c", "Alpha"),
            report_format("format-a", "Alpha"),
        ],
    );

    let Json(response) = get_delta_audit_report_formats(State(state), sync_context())
        .await
        .unwrap();

    assert_eq!(response.count, 3);
    assert_eq!(response.items[0].id, "format-a");
    assert_eq!(response.items[1].id, "format-c");
    assert_eq!(response.items[2].id, "format-b");
}

#[tokio::test]
async fn get_delta_audit_report_format_returns_matching_format() {
    let state = test_state(
        vec![],
        vec![],
        vec![],
        vec![report_format("compliance-delta", "Compliance Delta")],
    );

    let Json(response) = get_delta_audit_report_format(
        State(state),
        sync_context(),
        Path("compliance-delta".to_string()),
    )
    .await
    .unwrap();

    assert_eq!(response.id, "compliance-delta");
    assert_eq!(response.name, "Compliance Delta");
}

#[tokio::test]
async fn get_delta_audit_report_format_returns_delta_audit_not_found_error() {
    let state = test_state(vec![], vec![], vec![], vec![]);

    let response = match get_delta_audit_report_format(
        State(state),
        sync_context(),
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
    assert_eq!(body["code"], "delta_audit_report_format_not_found");
}

#[tokio::test]
async fn sync_delta_audit_report_formats_returns_audit_delta_count() {
    let state = test_state(
        vec![],
        vec![],
        vec![],
        vec![report_format("format-1", "Compliance Delta")],
    );

    let Json(response) = sync_delta_audit_report_formats(State(state), sync_context())
        .await
        .unwrap();

    assert_eq!(response.status, "ok");
    assert_eq!(response.count, 0);
}
