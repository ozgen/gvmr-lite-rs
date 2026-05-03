use std::fs;

use crate::{
    bind_listener, build_app_state,
    config::settings::{AuthMode, Settings},
};

fn test_settings(temp_dir: &std::path::Path) -> Settings {
    Settings {
        port: 0,
        report_formats_feed_dir: temp_dir.join("feed"),
        work_dir: temp_dir.join("work"),
        rebuild_on_start: false,
        auth_mode: AuthMode::None,
        api_key: None,
        api_key_header: "X-API-Key".to_string(),
        jwt_secret: None,
        jwt_audience: "".to_string(),
        jwt_issuer: "".to_string(),
        jwt_clock_skew_seconds: 0,
        required_scope_render: "".to_string(),
        required_scope_sync: "".to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        log_level: "info".to_string(),
        log_format: "compact".to_string(),
    }
}

#[tokio::test]
async fn build_app_state_initializes_empty_format_cache() {
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp_dir.path().join("feed")).unwrap();

    let settings = test_settings(temp_dir.path());

    let app_state = build_app_state(settings).unwrap();

    let cache = app_state.format_cache.read().await;
    assert_eq!(cache.list().len(), 0);
}

#[test]
fn build_app_state_fails_when_feed_dir_is_invalid() {
    let temp_dir = tempfile::tempdir().unwrap();

    let invalid_feed_path = temp_dir.path().join("feed-file");
    fs::write(&invalid_feed_path, b"not a directory").unwrap();

    let mut settings = test_settings(temp_dir.path());
    settings.report_formats_feed_dir = invalid_feed_path;

    let result = build_app_state(settings);

    assert!(result.is_err());
}

#[tokio::test]
async fn bind_listener_binds_to_random_available_port() {
    let listener = bind_listener(0).await.unwrap();

    let addr = listener.local_addr().unwrap();
    assert_ne!(addr.port(), 0);
}
