pub fn extract_bearer(authorization: Option<&str>) -> Option<String> {
    let authorization = authorization?;

    let (scheme, token) = authorization.split_once(' ')?;

    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim();

    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

#[cfg(test)]
#[path = "bearer_tests.rs"]
mod bearer_tests;
