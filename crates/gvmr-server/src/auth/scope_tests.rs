use super::*;

#[test]
fn require_scope_allows_non_jwt_modes() {
    let ctx = AuthContext::default();

    assert!(require_scope(&ctx, &AuthMode::None, "render").is_ok());
    assert!(require_scope(&ctx, &AuthMode::ApiKey, "render").is_ok());
}

#[test]
fn require_scope_allows_jwt_when_scope_exists() {
    let mut ctx = AuthContext::default();
    ctx.scopes.insert("render".to_string());

    assert!(require_scope(&ctx, &AuthMode::Jwt, "render").is_ok());
}

#[test]
fn require_scope_rejects_jwt_when_scope_is_missing() {
    let ctx = AuthContext::default();

    let err = require_scope(&ctx, &AuthMode::Jwt, "render").unwrap_err();

    assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
}

#[test]
fn require_scope_allows_empty_scope() {
    let ctx = AuthContext::default();

    assert!(require_scope(&ctx, &AuthMode::Jwt, "").is_ok());
}
