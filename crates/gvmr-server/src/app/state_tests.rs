use crate::app::state::AppState;

use crate::config::settings::{AuthMode, Settings};
use gvmr_core::service::format_cache::FormatCache;

fn test_settings() -> Settings {
    Settings {
        port: 8080,
        report_formats_feed_dir: "tests/feed".into(),
        work_dir: "tests/work".into(),

        auth_mode: AuthMode::None,

        api_key: None,
        api_key_header: "x-api-key".to_string(),

        jwt_secret: None,
        jwt_audience: String::new(),
        jwt_issuer: String::new(),
        jwt_clock_skew_seconds: 0,

        required_scope_render: String::new(),
        required_scope_sync: String::new(),

        max_body_bytes: 1,
        rebuild_on_start: false,

        log_level: "debug".to_string(),
        log_format: String::new(),
        experimental_enabled: false,
    }
}

fn test_cache(settings: &Settings) -> FormatCache {
    FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        settings.experimental_enabled,
    )
}

#[tokio::test]
async fn new_stores_settings_and_cache() {
    let settings = test_settings();
    let cache = test_cache(&settings);

    let state = AppState::new(settings.clone(), cache);

    assert_eq!(state.settings.port, settings.port);
    assert_eq!(state.settings.auth_mode, settings.auth_mode);
    assert_eq!(
        state.settings.report_formats_feed_dir,
        settings.report_formats_feed_dir
    );
    assert_eq!(state.settings.work_dir, settings.work_dir);

    let cache = state.format_cache.read().await;

    assert!(cache.list().is_empty());
}

#[test]
fn debug_formats_app_state_without_exposing_renderer_internals() {
    let settings = test_settings();
    let cache = test_cache(&settings);

    let state = AppState::new(settings, cache);

    let debug_output = format!("{state:?}");

    assert!(debug_output.contains("AppState"));
    assert!(debug_output.contains("settings"));
    assert!(debug_output.contains("format_cache"));
    assert!(debug_output.contains("renderer"));
    assert!(debug_output.contains("<dyn ReportRenderer>"));
}
