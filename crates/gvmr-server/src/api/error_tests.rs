use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
use serde_json::Value;

use crate::api::error::ApiError;

async fn response_body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn api_error_new_sets_status_code_and_message() {
    let error = ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_error",
        "invalid timeout",
    );

    assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error.code, "validation_error");
    assert_eq!(error.message, "invalid timeout");
}

#[test]
fn unauthorized_creates_401_error() {
    let error = ApiError::unauthorized("missing token");

    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "unauthorized");
    assert_eq!(error.message, "missing token");
}

#[test]
fn forbidden_creates_403_error() {
    let error = ApiError::forbidden("missing scope");

    assert_eq!(error.status(), StatusCode::FORBIDDEN);
    assert_eq!(error.code, "forbidden");
    assert_eq!(error.message, "missing scope");
}

#[test]
fn internal_creates_500_error() {
    let error = ApiError::internal("database failed");

    assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.code, "internal_error");
    assert_eq!(error.message, "database failed");
}

#[test]
fn not_found_creates_404_error_with_custom_code() {
    let error = ApiError::not_found(
        "report_format_not_found",
        "Report format not found: format-1",
    );

    assert_eq!(error.status(), StatusCode::NOT_FOUND);
    assert_eq!(error.code, "report_format_not_found");
    assert_eq!(error.message, "Report format not found: format-1");
}

#[tokio::test]
async fn api_error_into_response_returns_json_body() {
    let error = ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_error",
        "timeout_seconds must be between 1 and 1201",
    );

    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let body = response_body_json(response).await;

    assert_eq!(body["code"], "validation_error");
    assert_eq!(
        body["message"],
        "timeout_seconds must be between 1 and 1201"
    );
}
