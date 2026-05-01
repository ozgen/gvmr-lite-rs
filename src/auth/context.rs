use std::collections::HashSet;

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::api::error::ApiError;

#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    pub subject: Option<String>,
    pub scopes: HashSet<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .ok_or_else(|| ApiError::unauthorized("Missing auth context"))
    }
}
