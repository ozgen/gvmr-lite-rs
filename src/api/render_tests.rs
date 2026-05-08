use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
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
use serde_json::{Map, Value};

use crate::{
    api::{
        dto::{
            render::{RenderRequest, ReportJson},
            render_xml::RenderXmlRequest,
        },
        render::{render, render_xml},
    },
    app::state::AppState,
    auth::context::AuthContext,
    config::settings::{AuthMode, Settings},
    domain::report_format::{ReportFormat, ReportFormatFile},
    infra::fs::make_executable_best_effort,
    service::{
        format_cache::FormatCache,
        report_renderer::{RenderError, RenderResult, ReportRenderer},
    },
};

#[derive(Debug, Clone, Default)]
struct RecordedRenderCall {
    format_id: String,
    report_json: Value,
    params: Map<String, Value>,
    timeout_seconds: u64,
    output_name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum FakeRendererMode {
    Success,
    Failure,
    InvalidFilename,
}

#[derive(Debug)]
struct FakeRenderer {
    mode: FakeRendererMode,
    calls_count: AtomicUsize,
    last_call: Mutex<Option<RecordedRenderCall>>,
}

impl FakeRenderer {
    fn new(mode: FakeRendererMode) -> Self {
        Self {
            mode,
            calls_count: AtomicUsize::new(0),
            last_call: Mutex::new(None),
        }
    }

    fn calls_count(&self) -> usize {
        self.calls_count.load(Ordering::SeqCst)
    }

    fn last_call(&self) -> Option<RecordedRenderCall> {
        self.last_call.lock().unwrap().clone()
    }
}

#[async_trait]
impl ReportRenderer for FakeRenderer {
    async fn render(
        &self,
        fmt: &ReportFormat,
        report_json: &Value,
        params: &Map<String, Value>,
        timeout_seconds: u64,
        output_name: Option<&str>,
    ) -> Result<RenderResult, RenderError> {
        self.calls_count.fetch_add(1, Ordering::SeqCst);

        *self.last_call.lock().unwrap() = Some(RecordedRenderCall {
            format_id: fmt.id.clone(),
            report_json: report_json.clone(),
            params: params.clone(),
            timeout_seconds,
            output_name: output_name.map(ToOwned::to_owned),
        });

        match self.mode {
            FakeRendererMode::Success => Ok(RenderResult {
                filename: output_name.unwrap_or("report.json").to_string(),
                content_type: "application/json".to_string(),
                content: br#"{"status":"ok"}"#.to_vec(),
            }),
            FakeRendererMode::Failure => {
                Err(RenderError::BuildXml("fake renderer failed".to_string()))
            }
            FakeRendererMode::InvalidFilename => Ok(RenderResult {
                filename: "bad\nfilename.json".to_string(),
                content_type: "application/json".to_string(),
                content: br#"{"status":"ok"}"#.to_vec(),
            }),
        }
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

fn report_format(id: &str, name: &str, extension: &str, content_type: &str) -> ReportFormat {
    let workdir = PathBuf::from(format!("/tmp/work/report-formats/{id}"));

    ReportFormat::new(
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
    required_scope_render: &str,
    formats: Vec<ReportFormat>,
    renderer: Arc<dyn ReportRenderer>,
) -> AppState {
    let feed_dir = PathBuf::from("/tmp/feed");
    let work_dir = PathBuf::from("/tmp/work");

    let settings = test_settings(auth_mode, required_scope_render, feed_dir.clone(), work_dir);

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

    AppState::new_for_test(settings, format_cache, renderer)
}

fn render_request(format_id: &str) -> RenderRequest {
    RenderRequest {
        format_id: format_id.to_string(),
        report_json: ReportJson::default(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 300,
    }
}

fn render_request_with_options(format_id: &str) -> RenderRequest {
    let mut params = Map::new();
    params.insert(
        "timezone".to_string(),
        Value::String("Europe/Berlin".to_string()),
    );
    params.insert("debug".to_string(), Value::Bool(true));

    RenderRequest {
        format_id: format_id.to_string(),
        report_json: ReportJson {
            scan_run_status: Some("Done".to_string()),
            ..Default::default()
        },
        params,
        output_name: Some("custom-report.json".to_string()),
        timeout_seconds: 42,
    }
}

fn json_format() -> ReportFormat {
    report_format("format-1", "JSON Report", "json", "application/json")
}

async fn response_body_string(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    String::from_utf8(bytes.to_vec()).unwrap()
}

fn render_xml_request(format_id: &str) -> RenderXmlRequest {
    RenderXmlRequest {
        format_id: format_id.to_string(),
        report_xml: valid_report_xml().to_string(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 300,
    }
}

fn render_xml_request_with_options(format_id: &str) -> RenderXmlRequest {
    let mut params = Map::new();
    params.insert(
        "timezone".to_string(),
        Value::String("Europe/Berlin".to_string()),
    );
    params.insert("debug".to_string(), Value::Bool(true));

    RenderXmlRequest {
        format_id: format_id.to_string(),
        report_xml: valid_report_xml().to_string(),
        params,
        output_name: Some("custom-report.xml".to_string()),
        timeout_seconds: 42,
    }
}

fn valid_report_xml() -> &'static str {
    r#"<report id="outer-report" content_type="application/xml" extension="xml"><report id="inner-report"><scan_run_status>Done</scan_run_status><results></results></report></report>"#
}

fn xml_format_with_generate(script: &[u8]) -> ReportFormat {
    let workdir = temp_test_dir("xml-endpoint-format");

    fs::write(workdir.join("generate"), script).unwrap();
    make_executable_best_effort(&workdir.join("generate"));

    ReportFormat::new(
        "xml-format-1".to_string(),
        "XML Report".to_string(),
        "xml".to_string(),
        "application/xml".to_string(),
        workdir.clone(),
        vec![ReportFormatFile::new(
            "generate".to_string(),
            workdir.join("generate"),
        )],
    )
}

fn text_format_with_generate(script: &[u8]) -> ReportFormat {
    let workdir = temp_test_dir("xml-endpoint-text-format");

    fs::write(workdir.join("generate"), script).unwrap();
    make_executable_best_effort(&workdir.join("generate"));

    ReportFormat::new(
        "text-format-1".to_string(),
        "Text Report".to_string(),
        "txt".to_string(),
        "text/plain".to_string(),
        workdir.clone(),
        vec![ReportFormatFile::new(
            "generate".to_string(),
            workdir.join("generate"),
        )],
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
async fn render_returns_ok_response_with_headers_and_body() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(AuthMode::Jwt, "render", vec![json_format()], renderer);

    let response = render(
        State(state),
        auth_context_with_render_scope(),
        Json(render_request("format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/json"
    );

    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"report.json\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn render_passes_expected_values_to_renderer() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![json_format()],
        renderer.clone(),
    );

    let response = render(
        State(state),
        auth_context_with_render_scope(),
        Json(render_request_with_options("format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(renderer.calls_count(), 1);

    let call = renderer.last_call().unwrap();

    assert_eq!(call.format_id, "format-1");
    assert_eq!(call.timeout_seconds, 42);
    assert_eq!(call.output_name.as_deref(), Some("custom-report.json"));
    assert_eq!(
        call.params["timezone"],
        Value::String("Europe/Berlin".to_string())
    );
    assert_eq!(call.params["debug"], Value::Bool(true));
    assert_eq!(
        call.report_json["scan_run_status"],
        Value::String("Done".to_string())
    );
}

#[tokio::test]
async fn render_uses_renderer_filename_in_content_disposition_header() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(AuthMode::Jwt, "render", vec![json_format()], renderer);

    let response = render(
        State(state),
        auth_context_with_render_scope(),
        Json(render_request_with_options("format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"custom-report.json\""
    );
}

#[tokio::test]
async fn render_returns_forbidden_when_render_scope_is_missing() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![json_format()],
        renderer.clone(),
    );

    let response = match render(
        State(state),
        auth_context_without_render_scope(),
        Json(render_request("format-1")),
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
async fn render_returns_unprocessable_entity_when_timeout_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(
        AuthMode::Jwt,
        "render",
        vec![json_format()],
        renderer.clone(),
    );

    let mut request = render_request("format-1");
    request.timeout_seconds = 0;

    let response = match render(
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
}

#[tokio::test]
async fn render_returns_not_found_when_report_format_is_missing() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(AuthMode::Jwt, "render", vec![], renderer.clone());

    let response = match render(
        State(state),
        auth_context_with_render_scope(),
        Json(render_request("missing-format")),
    )
    .await
    {
        Ok(_) => panic!("expected not found error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(renderer.calls_count(), 0);
}

#[tokio::test]
async fn render_returns_internal_server_error_when_renderer_fails() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Failure));

    let state = test_state(AuthMode::Jwt, "render", vec![json_format()], renderer);

    let response = match render(
        State(state),
        auth_context_with_render_scope(),
        Json(render_request("format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected render failure"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response_body_string(response).await;

    assert!(body.contains("Render failed"));
    assert!(body.contains("fake renderer failed"));
}

#[tokio::test]
async fn render_returns_internal_server_error_when_content_disposition_filename_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::InvalidFilename));

    let state = test_state(AuthMode::Jwt, "render", vec![json_format()], renderer);

    let response = match render(
        State(state),
        auth_context_with_render_scope(),
        Json(render_request("format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected invalid content-disposition error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response_body_string(response).await;

    assert!(body.contains("Invalid content-disposition header"));
}

#[tokio::test]
async fn render_allows_access_when_auth_mode_is_none() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(AuthMode::None, "render", vec![json_format()], renderer);

    let response = render(
        State(state),
        AuthContext::default(),
        Json(render_request("format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn render_xml_returns_ok_response_with_headers_and_body() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\nprintf 'hello from xml endpoint'\n");

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let response = render_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(render_xml_request("xml-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/xml"
    );

    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"report.xml\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, "hello from xml endpoint");
}

#[tokio::test]
async fn render_xml_uses_requested_output_name_in_content_disposition_header() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\nprintf 'hello'\n");

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let response = render_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(render_xml_request_with_options("xml-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"custom-report.xml\""
    );
}

#[tokio::test]
async fn render_xml_passes_raw_xml_to_generate_script() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\ncat report.xml\n");

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let request = RenderXmlRequest {
        format_id: "xml-format-1".to_string(),
        report_xml: valid_report_xml().to_string(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 300,
    };

    let response = render_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(request),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body_string(response).await;

    assert_eq!(body, valid_report_xml());
}

#[tokio::test]
async fn render_xml_forwards_params_to_generate_script() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = text_format_with_generate(
        b"#!/bin/sh\nprintf \"%s:%s\" \"$GVMR_PARAM_TIMEZONE\" \"$GVMR_PARAM_DEBUG\"\n",
    );

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let response = render_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(render_xml_request_with_options("text-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "text/plain");

    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"custom-report.xml\""
    );

    let body = response_body_string(response).await;

    assert_eq!(body, "Europe/Berlin:true");
}

#[tokio::test]
async fn render_xml_returns_forbidden_when_render_scope_is_missing() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\nprintf 'should not run'\n");

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let response = match render_xml(
        State(state),
        auth_context_without_render_scope(),
        Json(render_xml_request("xml-format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected forbidden error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn render_xml_returns_unprocessable_entity_when_timeout_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\nprintf 'should not run'\n");

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let mut request = render_xml_request("xml-format-1");
    request.timeout_seconds = 0;

    let response = match render_xml(
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
}

#[tokio::test]
async fn render_xml_returns_not_found_when_report_format_is_missing() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let state = test_state(AuthMode::Jwt, "render", vec![], renderer);

    let response = match render_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(render_xml_request("missing-format")),
    )
    .await
    {
        Ok(_) => panic!("expected not found error"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn render_xml_returns_internal_server_error_when_xml_is_invalid() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\nprintf 'should not run'\n");

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let mut request = render_xml_request("xml-format-1");
    request.report_xml = "<foo></foo>".to_string();

    let response = match render_xml(
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

    let body = response_body_string(response).await;

    assert!(body.contains("Render failed"));
    assert!(body.contains("invalid report XML"));
}

#[tokio::test]
async fn render_xml_returns_internal_server_error_when_generate_script_is_missing() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let workdir = temp_test_dir("xml-endpoint-missing-generate");

    let format = ReportFormat::new(
        "xml-format-1".to_string(),
        "XML Report".to_string(),
        "xml".to_string(),
        "application/xml".to_string(),
        workdir.clone(),
        vec![],
    );

    let state = test_state(AuthMode::Jwt, "render", vec![format], renderer);

    let response = match render_xml(
        State(state),
        auth_context_with_render_scope(),
        Json(render_xml_request("xml-format-1")),
    )
    .await
    {
        Ok(_) => panic!("expected render failure"),
        Err(error) => error.into_response(),
    };

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response_body_string(response).await;

    assert!(body.contains("Render failed"));
    assert!(body.contains("generate script not found"));

    let _ = fs::remove_dir_all(workdir);
}

#[tokio::test]
async fn render_xml_allows_access_when_auth_mode_is_none() {
    let renderer = Arc::new(FakeRenderer::new(FakeRendererMode::Success));

    let format = xml_format_with_generate(b"#!/bin/sh\nprintf 'hello'\n");

    let state = test_state(AuthMode::None, "render", vec![format], renderer);

    let response = render_xml(
        State(state),
        AuthContext::default(),
        Json(render_xml_request("xml-format-1")),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
