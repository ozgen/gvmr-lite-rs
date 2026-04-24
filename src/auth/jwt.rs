use std::collections::HashSet;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::{
    api::error::ApiError,
    auth::context::AuthContext,
    config::settings::Settings,
};

#[derive(Debug, Deserialize)]
struct Claims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Option<String>,

    #[serde(default)]
    scope: Option<String>,

    #[serde(default)]
    scopes: Option<Vec<String>>,
}

pub fn validate_jwt(token: &str, settings: &Settings) -> Result<AuthContext, ApiError> {
    let Some(secret) = settings.jwt_secret.as_deref() else {
        return Err(ApiError::internal(
            "JWT auth enabled but GVMR_JWT_SECRET is not set",
        ));
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[settings.jwt_audience.as_str()]);
    validation.set_issuer(&[settings.jwt_issuer.as_str()]);
    validation.leeway = settings.jwt_clock_skew_seconds;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::unauthorized("Invalid token"))?;

    let claims = token_data.claims;

    if claims.iss.as_deref() != Some(settings.jwt_issuer.as_str()) {
        return Err(ApiError::unauthorized("Invalid token issuer"));
    }

    if claims.aud.as_deref() != Some(settings.jwt_audience.as_str()) {
        return Err(ApiError::unauthorized("Invalid token audience"));
    }

    let scopes = parse_scopes(claims.scope, claims.scopes);

    Ok(AuthContext {
        subject: claims.sub,
        scopes,
        issuer: claims.iss,
        audience: claims.aud,
    })
}

fn parse_scopes(scope: Option<String>, scopes: Option<Vec<String>>) -> HashSet<String> {
    let mut result = HashSet::new();

    if let Some(scope) = scope {
        for item in scope.split_whitespace() {
            result.insert(item.to_string());
        }
    }

    if let Some(scopes) = scopes {
        for item in scopes {
            if !item.trim().is_empty() {
                result.insert(item);
            }
        }
    }

    result
}