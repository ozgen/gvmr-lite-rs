use axum::{
    http::{Request, StatusCode},
    response::IntoResponse,
};

use super::*;

#[tokio::test]
async fn extracts_auth_context_from_request_extensions() {
    let expected = AuthContext {
        subject: Some("user-123".to_string()),
        audience: Some("gvmr-lite-rs".to_string()),
        issuer: Some("test-suite".to_string()),
        scopes: HashSet::from(["render".to_string()]),
    };

    let request = Request::builder().uri("/test").body(()).unwrap();

    let (mut parts, _) = request.into_parts();
    parts.extensions.insert(expected.clone());

    let actual = AuthContext::from_request_parts(&mut parts, &())
        .await
        .unwrap();

    assert_eq!(actual.subject, expected.subject);
    assert_eq!(actual.audience, expected.audience);
    assert_eq!(actual.issuer, expected.issuer);
    assert_eq!(actual.scopes, expected.scopes);
}

#[tokio::test]
async fn returns_unauthorized_when_auth_context_is_missing() {
    let request = Request::builder().uri("/test").body(()).unwrap();

    let (mut parts, _) = request.into_parts();

    let err = AuthContext::from_request_parts(&mut parts, &())
        .await
        .unwrap_err();

    let response = err.into_response();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
