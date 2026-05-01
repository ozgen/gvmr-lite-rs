use super::*;
use crate::config::settings::{AuthMode, Settings};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
}

#[test]
fn validate_jwt_accepts_valid_token_with_scope_string() {
    let settings = test_settings();

    let token = test_token(&settings, Some("render sync".to_string()), None);

    let ctx = validate_jwt(&token, &settings).unwrap();

    assert_eq!(ctx.subject.as_deref(), Some("user-1"));
    assert!(ctx.scopes.contains("render"));
    assert!(ctx.scopes.contains("sync"));
    assert_eq!(ctx.issuer.as_deref(), Some("test-issuer"));
    assert_eq!(ctx.audience.as_deref(), Some("test-audience"));
}

#[test]
fn validate_jwt_accepts_valid_token_with_scopes_array() {
    let settings = test_settings();

    let token = test_token(
        &settings,
        None,
        Some(vec!["render".to_string(), "sync".to_string()]),
    );

    let ctx = validate_jwt(&token, &settings).unwrap();

    assert!(ctx.scopes.contains("render"));
    assert!(ctx.scopes.contains("sync"));
}

#[test]
fn validate_jwt_returns_error_when_secret_is_missing() {
    let mut settings = test_settings();
    settings.jwt_secret = None;

    let err = validate_jwt("token", &settings).unwrap_err();

    assert_eq!(err.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn validate_jwt_rejects_invalid_token() {
    let settings = test_settings();

    let err = validate_jwt("not-a-jwt", &settings).unwrap_err();

    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[test]
fn validate_jwt_rejects_wrong_issuer() {
    let settings = test_settings();

    let claims = TestClaims {
        sub: "user-1".to_string(),
        iss: "wrong-issuer".to_string(),
        aud: settings.jwt_audience.clone(),
        exp: future_exp(),
        scope: Some("render".to_string()),
        scopes: None,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.as_ref().unwrap().as_bytes()),
    )
    .unwrap();

    let err = validate_jwt(&token, &settings).unwrap_err();

    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[test]
fn validate_jwt_rejects_wrong_audience() {
    let settings = test_settings();

    let claims = TestClaims {
        sub: "user-1".to_string(),
        iss: settings.jwt_issuer.clone(),
        aud: "wrong-audience".to_string(),
        exp: future_exp(),
        scope: Some("render".to_string()),
        scopes: None,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.as_ref().unwrap().as_bytes()),
    )
    .unwrap();

    let err = validate_jwt(&token, &settings).unwrap_err();

    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[test]
fn parse_scopes_combines_scope_string_and_scopes_array() {
    let scopes = parse_scopes(
        Some("render sync".to_string()),
        Some(vec!["admin".to_string(), "render".to_string()]),
    );

    assert!(scopes.contains("render"));
    assert!(scopes.contains("sync"));
    assert!(scopes.contains("admin"));
    assert_eq!(scopes.len(), 3);
}

fn test_token(settings: &Settings, scope: Option<String>, scopes: Option<Vec<String>>) -> String {
    let claims = TestClaims {
        sub: "user-1".to_string(),
        iss: settings.jwt_issuer.clone(),
        aud: settings.jwt_audience.clone(),
        exp: future_exp(),
        scope,
        scopes,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.as_ref().unwrap().as_bytes()),
    )
    .unwrap()
}

fn future_exp() -> usize {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    (now + 3600) as usize
}

fn test_settings() -> Settings {
    Settings {
        port: 8080,
        report_formats_feed_dir: "tests/feed".into(),
        work_dir: "tests/work".into(),
        rebuild_on_start: false,

        auth_mode: AuthMode::Jwt,
        api_key: None,
        api_key_header: "x-api-key".to_string(),

        jwt_secret: Some("test-secret".to_string()),
        jwt_audience: "test-audience".to_string(),
        jwt_issuer: "test-issuer".to_string(),
        jwt_clock_skew_seconds: 30,

        required_scope_render: "render".to_string(),
        required_scope_sync: "sync".to_string(),

        log_level: "debug".to_string(),
        max_body_bytes: 1024 * 1024,
        log_format: "pretty".to_string(),
    }
}
