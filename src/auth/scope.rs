use crate::{api::error::ApiError, auth::context::AuthContext};

#[allow(dead_code)]
pub fn require_scope(ctx: &AuthContext, scope: &str) -> Result<(), ApiError> {
    if !ctx.scopes.contains(scope) {
        return Err(ApiError::forbidden(format!("Missing scope: {scope}")));
    }

    Ok(())
}
