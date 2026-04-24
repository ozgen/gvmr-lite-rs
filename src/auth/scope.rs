use crate::{api::error::ApiError, auth::context::AuthContext, config::settings::AuthMode};

pub fn require_scope(ctx: &AuthContext, auth_mode: &AuthMode, scope: &str) -> Result<(), ApiError> {
    if !matches!(auth_mode, AuthMode::Jwt) {
        return Ok(());
    }

    if !scope.is_empty() && !ctx.scopes.contains(scope) {
        return Err(ApiError::forbidden(format!("Missing scope: {scope}")));
    }

    Ok(())
}
