use super::*;

#[test]
fn extracts_token_from_valid_bearer_header() {
    let token = extract_bearer(Some("Bearer abc123"));

    assert_eq!(token, Some("abc123".to_string()));
}

#[test]
fn extracts_token_case_insensitively() {
    let token = extract_bearer(Some("bearer abc123"));

    assert_eq!(token, Some("abc123".to_string()));
}

#[test]
fn trims_token_whitespace() {
    let token = extract_bearer(Some("Bearer   abc123   "));

    assert_eq!(token, Some("abc123".to_string()));
}

#[test]
fn returns_none_when_header_is_missing() {
    let token = extract_bearer(None);

    assert_eq!(token, None);
}

#[test]
fn returns_none_when_scheme_is_not_bearer() {
    let token = extract_bearer(Some("Basic abc123"));

    assert_eq!(token, None);
}

#[test]
fn returns_none_when_token_is_empty() {
    let token = extract_bearer(Some("Bearer "));

    assert_eq!(token, None);
}

#[test]
fn returns_none_when_header_has_no_space() {
    let token = extract_bearer(Some("Bearerabc123"));

    assert_eq!(token, None);
}
