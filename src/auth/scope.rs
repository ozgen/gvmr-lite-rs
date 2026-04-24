use axum::http::Request;

use crate::{
    api::error::ApiError,
    auth::context::AuthContext,
};

#[allow(dead_code)]
pub fn require_scope(
    req: &Request<axum::body::Body>,
    scope: &str,
) -> Result<(), ApiError> {
    let ctx = req
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ApiError::unauthorized("Missing auth context"))?;

    if !ctx.scopes.contains(scope) {
        return Err(ApiError::forbidden(format!("Missing scope: {scope}")));
    }

    Ok(())
}