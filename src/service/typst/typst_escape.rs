pub fn typst_text_expr(value: &str) -> String {
    format!("#text({})", typst_string_literal(value))
}

pub fn optional_typst_text_expr(value: Option<String>) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => typst_string_literal(&value),
        _ => "none".to_string(),
    }
}

pub fn typst_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');

    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => {}
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }

    escaped.push('"');
    escaped
}

pub fn escape_typst_markup(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('#', "\\#")
}

pub fn sanitize_typst_label(value: &str) -> String {
    let mut out = String::new();

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }

    while out.contains("--") {
        out = out.replace("--", "-");
    }

    let cleaned = out.trim_matches('-');

    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned.to_string()
    }
}

#[cfg(test)]
#[path = "typst_escape_tests.rs"]
mod typst_escape_tests;
