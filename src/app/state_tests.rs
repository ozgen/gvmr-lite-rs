use crate::{
    app::state::AppState,
    config::settings::{AuthMode, Settings},
    service::format_cache::FormatCache,
};

fn test_settings() -> Settings {
    Settings {
        port: 8080,
        report_formats_feed_dir: "tests/feed".into(),
        work_dir: "tests/work".into(),
        rebuild_on_start: false,
        auth_mode: AuthMode::None,
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
        log_format: String::new(),
    }
}

#[tokio::test]
async fn new_stores_settings_and_cache() {
    let settings = test_settings();

    let cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.work_dir.clone(),
        settings.rebuild_on_start,
    );

    let state = AppState::new(settings.clone(), cache);

    assert_eq!(state.settings.port, settings.port);
    assert_eq!(state.settings.auth_mode, settings.auth_mode);

    let _cache = state.format_cache.read().await;
}

#[test]
fn new_stores_settings() {
    let settings = test_settings();

    let cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.work_dir.clone(),
        settings.rebuild_on_start,
    );

    let state = AppState::new(settings.clone(), cache);

    assert_eq!(state.settings.port, settings.port);
    assert_eq!(state.settings.auth_mode, settings.auth_mode);
}