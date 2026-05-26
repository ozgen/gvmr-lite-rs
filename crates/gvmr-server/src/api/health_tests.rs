use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State};

use crate::{
    api::health::{live, ready},
    app::state::AppState,
};

use crate::config::settings::{AuthMode, Settings};
use gvmr_core::service::format_cache::FormatCache;

fn unique_test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    std::env::temp_dir().join(format!("gvmr-lite-rs-{name}-{nanos}"))
}

fn test_settings(feed_dir: PathBuf, work_dir: PathBuf) -> Settings {
    Settings {
        port: 8084,
        report_formats_feed_dir: feed_dir,
        work_dir,

        auth_mode: AuthMode::None,

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

fn test_state(feed_dir: PathBuf, work_dir: PathBuf) -> AppState {
    let settings = test_settings(feed_dir, work_dir);

    let format_cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        settings.experimental_enabled,
    );

    AppState::new(settings, format_cache)
}

#[tokio::test]
async fn live_returns_ok_status() {
    let Json(response) = live().await;

    assert_eq!(response.status, "ok");
}

#[tokio::test]
async fn ready_returns_ok_when_feed_dir_exists() {
    let feed_dir = unique_test_dir("ready-feed-exists");
    let work_dir = unique_test_dir("ready-work-exists");

    fs::create_dir_all(&feed_dir).unwrap();
    fs::create_dir_all(work_dir.join("report-formats")).unwrap();

    let state = test_state(feed_dir.clone(), work_dir.clone());

    let Json(response) = ready(State(state)).await;

    assert_eq!(response.status, "ok");
    assert_eq!(response.feed_dir, feed_dir.display().to_string());
    assert_eq!(
        response.work_dir,
        work_dir.join("report-formats").display().to_string()
    );
    assert!(response.feed_exists);
    assert!(response.work_exists);
    assert_eq!(response.formats_count, 0);

    fs::remove_dir_all(&feed_dir).unwrap();
    fs::remove_dir_all(&work_dir).unwrap();
}

#[tokio::test]
async fn ready_returns_not_ready_when_feed_dir_does_not_exist() {
    let feed_dir = unique_test_dir("ready-feed-missing");
    let work_dir = unique_test_dir("ready-work-present");

    fs::create_dir_all(work_dir.join("report-formats")).unwrap();

    let state = test_state(feed_dir.clone(), work_dir.clone());

    let Json(response) = ready(State(state)).await;

    assert_eq!(response.status, "not_ready");
    assert_eq!(response.feed_dir, feed_dir.display().to_string());
    assert_eq!(
        response.work_dir,
        work_dir.join("report-formats").display().to_string()
    );
    assert!(!response.feed_exists);
    assert!(response.work_exists);
    assert_eq!(response.formats_count, 0);

    fs::remove_dir_all(&work_dir).unwrap();
}

#[tokio::test]
async fn ready_reports_work_exists_false_when_report_formats_work_dir_is_missing() {
    let feed_dir = unique_test_dir("ready-feed-present");
    let work_dir = unique_test_dir("ready-work-missing");

    fs::create_dir_all(&feed_dir).unwrap();

    let state = test_state(feed_dir.clone(), work_dir.clone());

    let Json(response) = ready(State(state)).await;

    assert_eq!(response.status, "ok");
    assert!(response.feed_exists);
    assert!(!response.work_exists);
    assert_eq!(
        response.work_dir,
        work_dir.join("report-formats").display().to_string()
    );

    fs::remove_dir_all(&feed_dir).unwrap();
}
