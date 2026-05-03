use crate::config::settings::{AuthMode, RawSettings, Settings};
use serial_test::serial;
use std::env;
use std::{path::PathBuf, str::FromStr};

fn raw_settings() -> RawSettings {
    RawSettings {
        port: 8084,
        report_formats_feed_dir: PathBuf::from("/feed"),
        work_dir: PathBuf::from("/work"),
        auth_mode: "none".to_string(),
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
    }
}

fn clear_gvmr_env() {
    for key in [
        "GVMR_PORT",
        "GVMR_AUTH_MODE",
        "GVMR_MAX_BODY_BYTES",
        "GVMR_API_KEY_HEADER",
    ] {
        unsafe {
            env::remove_var(key);
        }
    }
}

#[test]
#[serial]
fn load_uses_defaults_when_env_is_missing() {
    clear_gvmr_env();

    let settings = Settings::load().unwrap();

    assert_eq!(settings.port, 8084);
    assert_eq!(settings.auth_mode, AuthMode::None);
    assert_eq!(settings.max_body_bytes, 50 * 1024 * 1024);

    clear_gvmr_env();
}

#[test]
#[serial]
fn load_uses_gvmr_environment_overrides() {
    clear_gvmr_env();

    unsafe {
        env::set_var("GVMR_PORT", "9090");
        env::set_var("GVMR_AUTH_MODE", "jwt");
        env::set_var("GVMR_MAX_BODY_BYTES", "12345");
        env::set_var("GVMR_API_KEY_HEADER", "X-Test-Key");
    }

    let settings = Settings::load().unwrap();

    assert_eq!(settings.port, 9090);
    assert_eq!(settings.auth_mode, AuthMode::Jwt);
    assert_eq!(settings.max_body_bytes, 12345);
    assert_eq!(settings.api_key_header, "X-Test-Key");

    clear_gvmr_env();
}

#[test]
#[serial]
fn load_rejects_invalid_env_values() {
    clear_gvmr_env();

    unsafe {
        env::set_var("GVMR_AUTH_MODE", "basic");
    }

    let err = Settings::load().unwrap_err();

    assert!(err.to_string().contains("invalid auth_mode"));

    clear_gvmr_env();
}

#[test]
fn auth_mode_from_str_accepts_valid_values() {
    assert_eq!(AuthMode::from_str("none").unwrap(), AuthMode::None);
    assert_eq!(AuthMode::from_str("api_key").unwrap(), AuthMode::ApiKey);
    assert_eq!(AuthMode::from_str("jwt").unwrap(), AuthMode::Jwt);
}

#[test]
fn auth_mode_from_str_trims_and_is_case_insensitive() {
    assert_eq!(AuthMode::from_str(" JWT ").unwrap(), AuthMode::Jwt);
    assert_eq!(AuthMode::from_str(" API_KEY ").unwrap(), AuthMode::ApiKey);
}

#[test]
fn auth_mode_from_str_rejects_invalid_value() {
    let err = AuthMode::from_str("basic").unwrap_err();

    assert!(err.to_string().contains("invalid auth_mode"));
}

#[test]
fn config_builder_provides_expected_defaults() {
    let config = Settings::config_builder().unwrap().build().unwrap();

    let raw = config.try_deserialize::<RawSettings>().unwrap();
    let settings = Settings::from_raw(raw).unwrap();

    assert_eq!(settings.port, 8084);
    assert_eq!(
        settings.report_formats_feed_dir,
        PathBuf::from("/var/lib/gvm/data-objects/gvmd/report-formats")
    );
    assert_eq!(settings.work_dir, PathBuf::from("/tmp/gvmr-lite/work"));
    assert_eq!(settings.auth_mode, AuthMode::None);
    assert_eq!(settings.api_key_header, "X-API-Key");
    assert_eq!(settings.jwt_audience, "gvmr-lite");
    assert_eq!(settings.jwt_issuer, "gvmd-lite");
    assert_eq!(settings.jwt_clock_skew_seconds, 300);
    assert_eq!(settings.required_scope_render, "render");
    assert_eq!(settings.required_scope_sync, "sync");
    assert_eq!(settings.max_body_bytes, 50 * 1024 * 1024);
    assert!(settings.rebuild_on_start);
    assert_eq!(settings.log_level, "info");
    assert_eq!(settings.log_format, "pretty");
}

#[test]
fn from_raw_builds_settings() {
    let settings = Settings::from_raw(raw_settings()).unwrap();

    assert_eq!(settings.port, 8084);
    assert_eq!(settings.report_formats_feed_dir, PathBuf::from("/feed"));
    assert_eq!(settings.work_dir, PathBuf::from("/work"));
    assert_eq!(settings.auth_mode, AuthMode::None);
    assert_eq!(settings.api_key_header, "X-API-Key");
    assert_eq!(settings.jwt_audience, "gvmr-lite");
    assert_eq!(settings.jwt_issuer, "gvmd-lite");
    assert_eq!(settings.required_scope_render, "render");
    assert_eq!(settings.required_scope_sync, "sync");
    assert_eq!(settings.max_body_bytes, 50 * 1024 * 1024);
    assert!(settings.rebuild_on_start);
}

#[test]
fn from_raw_rejects_zero_port() {
    let mut raw = raw_settings();
    raw.port = 0;

    let err = Settings::from_raw(raw).unwrap_err();

    assert!(err.to_string().contains("port must be between 1 and 65535"));
}

#[test]
fn from_raw_rejects_zero_max_body_bytes() {
    let mut raw = raw_settings();
    raw.max_body_bytes = 0;

    let err = Settings::from_raw(raw).unwrap_err();

    assert!(
        err.to_string()
            .contains("max_body_bytes must be greater than 0")
    );
}

#[test]
fn from_raw_rejects_invalid_auth_mode() {
    let mut raw = raw_settings();
    raw.auth_mode = "basic".to_string();

    let err = Settings::from_raw(raw).unwrap_err();

    assert!(err.to_string().contains("invalid auth_mode"));
}

#[test]
fn report_formats_work_dir_joins_report_formats() {
    let settings = Settings::from_raw(raw_settings()).unwrap();

    assert_eq!(
        settings.report_formats_work_dir(),
        PathBuf::from("/work/report-formats")
    );
}
