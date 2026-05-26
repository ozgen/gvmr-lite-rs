use crate::config::settings::AuthMode;
use crate::{api::error::ApiError, auth::context::AuthContext};

pub fn require_scope(ctx: &AuthContext, auth_mode: &AuthMode, scope: &str) -> Result<(), ApiError> {
    if !matches!(auth_mode, AuthMode::Jwt) {
        return Ok(());
    }

    if !scope.is_empty() && !ctx.scopes.contains(scope) {
        return Err(ApiError::forbidden(format!("Missing scope: {scope}")));
    }

    Ok(())
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod scope_tests;
