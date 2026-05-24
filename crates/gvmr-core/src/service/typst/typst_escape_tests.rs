use super::*;

#[test]
fn typst_string_literal_wraps_value_in_quotes() {
    assert_eq!(typst_string_literal("hello"), "\"hello\"");
}

#[test]
fn typst_string_literal_escapes_quotes_and_backslashes() {
    assert_eq!(
        typst_string_literal(r#"a "quoted" \ value"#),
        r#""a \"quoted\" \\ value""#
    );
}

#[test]
fn typst_string_literal_escapes_newlines_and_tabs() {
    assert_eq!(
        typst_string_literal("hello\nworld\t!"),
        "\"hello\\nworld\\t!\""
    );
}

#[test]
fn escape_typst_markup_escapes_markup_special_chars() {
    assert_eq!(escape_typst_markup(r#"a [b] #c \d"#), r#"a \[b\] \#c \\d"#);
}

#[test]
fn sanitize_typst_label_normalizes_text() {
    assert_eq!(sanitize_typst_label("Host 192.168.1.1"), "host-192-168-1-1");
}

#[test]
fn sanitize_typst_label_returns_unknown_for_empty_result() {
    assert_eq!(sanitize_typst_label("----"), "unknown");
}

#[test]
fn typst_text_expr_builds_text_expression() {
    assert_eq!(typst_text_expr("hello"), "#text(\"hello\")");
}

#[test]
fn optional_typst_text_expr_returns_none_for_empty_value() {
    assert_eq!(optional_typst_text_expr(Some("   ".to_string())), "none");
    assert_eq!(optional_typst_text_expr(None), "none");
}
