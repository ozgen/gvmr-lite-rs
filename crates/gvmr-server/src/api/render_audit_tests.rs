use super::{render_audit, render_audit_xml};

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    Json,
    body::to_bytes,
    extract::State,
    http::{
        StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    },
    response::IntoResponse,
};
use serde_json::{Map, Value, json};

use crate::{
    api::dto::{render_audit::RenderAuditRequest, render_audit_xml::RenderAuditXmlRequest},
    app::state::AppState,
    auth::context::AuthContext,
    config::settings::{AuthMode, Settings},
};

use gvmr_core::{
    domain::{
        report_format::{ReportFormat, ReportFormatFile},
        report_format_constants::{BUILT_IN_NATIVE_PDF_TECHNICAL_ID, BUILT_IN_TYPST_TECHNICAL_ID},
    },
    infra::fs::make_executable_best_effort,
    service::{
        format_cache::FormatCache,
        report_renderer::{RenderError, RenderResult, ReportRenderer},
    },
};

#[derive(Debug)]
struct FakeRenderer {
    calls_count: AtomicUsize,
}

impl FakeRenderer {
    fn new() -> Self {
        Self {
            calls_count: AtomicUsize::new(0),
        }
    }

    fn calls_count(&self) -> usize {
        self.calls_count.load(Ordering::SeqCst)
    }
}

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
        self.calls_count.fetch_add(1, Ordering::SeqCst);

        Ok(RenderResult {
            filename: "unused.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            content: b"unused".to_vec(),
        })
    }
}

fn test_settings(
    auth_mode: AuthMode,
    required_scope_render: &str,
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

        required_scope_render: required_scope_render.to_string(),
        required_scope_sync: "sync".to_string(),

        max_body_bytes: 50 * 1024 * 1024,

        rebuild_on_start: true,

        log_level: "info".to_string(),
        log_format: "pretty".to_string(),
        experimental_enabled: false,
    }
}

fn auth_context_with_render_scope() -> AuthContext {
    AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["render".to_string()]),
        ..Default::default()
    }
}

fn auth_context_without_render_scope() -> AuthContext {
    AuthContext {
        subject: Some("user-123".to_string()),
        scopes: HashSet::from(["sync".to_string()]),
        ..Default::default()
    }
}

fn test_state(
    auth_mode: AuthMode,
    required_scope_render: &str,
    audit_formats: Vec<ReportFormat>,
    renderer: Arc<dyn ReportRenderer>,
) -> AppState {
    let feed_dir = temp_test_dir("audit-feed");
    let work_dir = temp_test_dir("audit-work");

    let settings = test_settings(auth_mode, required_scope_render, feed_dir.clone(), work_dir);

    let audit_formats = audit_formats
        .into_iter()
        .map(|format| (format.id.clone(), format))
        .collect::<HashMap<_, _>>();

    let format_cache = FormatCache::new_for_test_with_audit_formats(
        feed_dir,
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        HashMap::new(),
        audit_formats,
    );

    AppState::new_for_test(settings, format_cache, renderer)
}

fn audit_render_request(format_id: &str) -> RenderAuditRequest {
    serde_json::from_value(json!({
        "format_id": format_id,
        "report_json": {
            "report": {
                "scan_run_status": "Done"
            }
        },
        "params": {},
        "output_name": null,
        "timeout_seconds": 300
    }))
    .expect("audit render request should deserialize")
}

fn audit_render_request_with_options(format_id: &str) -> RenderAuditRequest {
    serde_json::from_value(json!({
        "format_id": format_id,
        "report_json": {
            "@attrs": {
                "id": "outer-report"
            },
            "name": "Audit report",
            "report": {
                "scan_run_status": "Done"
            }
        },
        "params": {
            "timezone": "Europe/Berlin",
            "debug": true
        },
        "output_name": "custom-audit-report.pdf",
        "timeout_seconds": 42
    }))
    .expect("audit render request should deserialize")
}

fn feed_audit_format(script: &[u8]) -> ReportFormat {
    let workdir = temp_test_dir("audit-feed-format");
    let generate_path = workdir.join("generate");

    fs::write(&generate_path, script).unwrap();
    make_executable_best_effort(&generate_path);

    ReportFormat::feed(
        "audit-format-1".to_string(),
        "Audit PDF Report".to_string(),
        "pdf".to_string(),
        "application/pdf".to_string(),
        workdir.clone(),
        vec![ReportFormatFile::new("generate".to_string(), generate_path)],
    )
}

fn typst_audit_format() -> ReportFormat {
    let workdir = temp_test_dir("audit-typst-format");

    ReportFormat::built_in_typst(
        BUILT_IN_TYPST_TECHNICAL_ID,
        "Typst Technical Report",
        "pdf",
        "application/pdf",
        workdir,
    )
}

fn native_pdf_audit_format() -> ReportFormat {
    let workdir = temp_test_dir("audit-native-pdf-format");

    ReportFormat::built_in_native_pdf(
        BUILT_IN_NATIVE_PDF_TECHNICAL_ID,
        "Native PDF Technical Report",
        "pdf",
        "application/pdf",
        workdir,
    )
}

async fn response_body_string(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    String::from_utf8(bytes.to_vec()).unwrap()
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

fn valid_audit_report_xml() -> &'static str {
    r#"<report id="outer-report"><report id="inner-report"><scan_run_status>Done</scan_run_status><results></results></report></report>"#
}

fn audit_xml_request(format_id: &str) -> RenderAuditXmlRequest {
    RenderAuditXmlRequest {
        format_id: format_id.to_string(),
        report_xml: valid_audit_report_xml().to_string(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 300,
    }
}

fn audit_xml_request_with_options(format_id: &str) -> RenderAuditXmlRequest {
    let mut params = Map::new();
    params.insert(
        "timezone".to_string(),
        Value::String("Europe/Berlin".to_string()),
    );
    params.insert("debug".to_string(), Value::Bool(true));

    RenderAuditXmlRequest {
        format_id: format_id.to_string(),
        report_xml: valid_audit_report_xml().to_string(),
        params,
        output_name: Some("custom-audit-report.pdf".to_string()),
        timeout_seconds: 42,
    }
}

#[tokio::test]
async fn render_audit_returns_ok_response_with_headers_and_body() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'fake audit pdf'\n")],
        renderer.clone(),
    );

    let response = render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_render_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/pdf"
    );
    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"report.pdf\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, "fake audit pdf");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_forwards_params_and_output_name_to_generate_script() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf \"%s:%s\" \"$GVMR_PARAM_TIMEZONE\" \"$GVMR_PARAM_DEBUG\"\n",
        )],
        renderer.clone(),
    );

    let response = render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_render_request_with_options("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"custom-audit-report.pdf\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, "Europe/Berlin:true");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_returns_forbidden_when_render_scope_is_missing() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'should not run'\n")],
        renderer.clone(),
    );

    let response = match render_audit(
        State(state),
        auth_context_without_render_scope(),
        Json(audit_render_request("audit-format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_allows_access_when_auth_mode_is_none() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::None,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'fake audit pdf'\n")],
        renderer.clone(),
    );

    let response = render_audit(
        State(state),
        AuthContext::default(),
        Json(audit_render_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body_string(response).await;

    assert_eq!(body, "fake audit pdf");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_allows_jwt_access_when_required_render_scope_is_empty() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'fake audit pdf'\n")],
        renderer.clone(),
    );

    let response = render_audit(
        State(state),
        auth_context_without_render_scope(),
        Json(audit_render_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body_string(response).await;

    assert_eq!(body, "fake audit pdf");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_returns_unprocessable_entity_when_request_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'should not run'\n")],
        renderer.clone(),
    );

    let mut request = audit_render_request("audit-format-1");
    request.timeout_seconds = 0;

    let response = match render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(request),
    )
    .await
    {
        Ok(_) => panic!("expected validation error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("validation_error"));
    assert!(body.contains("timeout_seconds must be between 1 and 40001"));
}

#[tokio::test]
async fn render_audit_returns_not_found_when_audit_report_format_is_missing() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(AuthMode::Jwt, "render", vec![], renderer.clone());

    let response = match render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_render_request("missing-format")),
    )
    .await
    {
        Ok(_) => panic!("expected not found error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("audit_report_format_not_found"));
    assert!(body.contains("missing-format"));
}

#[tokio::test]
async fn render_audit_returns_internal_server_error_when_generate_script_fails() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf 'fake generate failed' >&2\nexit 1\n",
        )],
        renderer.clone(),
    );

    let response = match render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_render_request("audit-format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected render failure"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("Audit render failed"));
}

#[tokio::test]
async fn render_audit_returns_unprocessable_entity_for_typst_backend() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![typst_audit_format()],
        renderer.clone(),
    );

    let response = match render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_render_request(BUILT_IN_TYPST_TECHNICAL_ID)),
    )
    .await
    {
        Ok(_) => panic!("expected unsupported backend error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("unsupported_audit_renderer_backend"));
}

#[tokio::test]
async fn render_audit_returns_unprocessable_entity_for_native_pdf_backend() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![native_pdf_audit_format()],
        renderer.clone(),
    );

    let response = match render_audit(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_render_request(BUILT_IN_NATIVE_PDF_TECHNICAL_ID)),
    )
    .await
    {
        Ok(_) => panic!("expected unsupported backend error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("unsupported_audit_renderer_backend"));
}

#[tokio::test]
async fn render_audit_xml_returns_ok_response_with_headers_and_body() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf 'fake audit xml pdf'\n",
        )],
        renderer.clone(),
    );

    let response = render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/pdf"
    );
    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"report.pdf\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, "fake audit xml pdf");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_xml_passes_raw_xml_to_generate_script() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\ncat report.xml\n")],
        renderer.clone(),
    );

    let response = render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body_string(response).await;

    assert_eq!(body, valid_audit_report_xml());
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_xml_forwards_params_and_output_name_to_generate_script() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf \"%s:%s\" \"$GVMR_PARAM_TIMEZONE\" \"$GVMR_PARAM_DEBUG\"\n",
        )],
        renderer.clone(),
    );

    let response = render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request_with_options("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"custom-audit-report.pdf\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, "Europe/Berlin:true");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_xml_returns_forbidden_when_render_scope_is_missing() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'should not run'\n")],
        renderer.clone(),
    );

    let response = match render_audit_xml(
        State(state),
        auth_context_without_render_scope(),
        Json(audit_xml_request("audit-format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_xml_allows_access_when_auth_mode_is_none() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::None,
        "render",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf 'fake audit xml pdf'\n",
        )],
        renderer.clone(),
    );

    let response = render_audit_xml(
        State(state),
        AuthContext::default(),
        Json(audit_xml_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body_string(response).await;

    assert_eq!(body, "fake audit xml pdf");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_xml_allows_jwt_access_when_required_render_scope_is_empty() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf 'fake audit xml pdf'\n",
        )],
        renderer.clone(),
    );

    let response = render_audit_xml(
        State(state),
        auth_context_without_render_scope(),
        Json(audit_xml_request("audit-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body_string(response).await;

    assert_eq!(body, "fake audit xml pdf");
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_audit_xml_returns_unprocessable_entity_when_request_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'should not run'\n")],
        renderer.clone(),
    );

    let mut request = audit_xml_request("audit-format-1");
    request.report_xml = "   ".to_string();

    let response = match render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(request),
    )
    .await
    {
        Ok(_) => panic!("expected validation error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("validation_error"));
    assert!(body.contains("report_xml must not be empty"));
}

#[tokio::test]
async fn render_audit_xml_returns_not_found_when_audit_report_format_is_missing() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(AuthMode::Jwt, "render", vec![], renderer.clone());

    let response = match render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request("missing-format")),
    )
    .await
    {
        Ok(_) => panic!("expected not found error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("audit_report_format_not_found"));
    assert!(body.contains("missing-format"));
}

#[tokio::test]
async fn render_audit_xml_returns_internal_server_error_when_xml_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(b"#!/bin/sh\nprintf 'should not run'\n")],
        renderer.clone(),
    );

    let mut request = audit_xml_request("audit-format-1");
    request.report_xml = "<foo></foo>".to_string();

    let response = match render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(request),
    )
    .await
    {
        Ok(_) => panic!("expected invalid XML error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("Render failed"));
}

#[tokio::test]
async fn render_audit_xml_returns_internal_server_error_when_generate_script_fails() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![feed_audit_format(
            b"#!/bin/sh\nprintf 'fake generate failed' >&2\nexit 1\n",
        )],
        renderer.clone(),
    );

    let response = match render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request("audit-format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected render failure"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("Render failed"));
}

#[tokio::test]
async fn render_audit_xml_returns_unprocessable_entity_for_typst_backend() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![typst_audit_format()],
        renderer.clone(),
    );

    let response = match render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request(BUILT_IN_TYPST_TECHNICAL_ID)),
    )
    .await
    {
        Ok(_) => panic!("expected unsupported backend error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("unsupported_audit_renderer_backend"));
    assert!(body.contains("Audit XML rendering is currently only supported"));
}

#[tokio::test]
async fn render_audit_xml_returns_unprocessable_entity_for_native_pdf_backend() {
    let renderer = Arc::new(FakeRenderer::new());

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![native_pdf_audit_format()],
        renderer.clone(),
    );

    let response = match render_audit_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(audit_xml_request(BUILT_IN_NATIVE_PDF_TECHNICAL_ID)),
    )
    .await
    {
        Ok(_) => panic!("expected unsupported backend error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(renderer.calls_count(), 0);

    let body = response_body_string(response).await;

    assert!(body.contains("unsupported_audit_renderer_backend"));
    assert!(body.contains("Audit XML rendering is currently only supported"));
}
