use axum::{
    http::{Request, StatusCode},
    response::IntoResponse,
};

use super::*;

#[tokio::test]
async fn extracts_auth_context_from_request_extensions() {
    let mut expected = AuthContext::default();
    expected.subject = Some("user-123".to_string());
    expected.scopes.insert("render".to_string());

    let request = Request::builder().uri("/test").body(()).unwrap();

    let (mut parts, _) = request.into_parts();
    parts.extensions.insert(expected.clone());

    let actual = AuthContext::from_request_parts(&mut parts, &())
        .await
        .unwrap();

    assert_eq!(actual.subject, expected.subject);
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
