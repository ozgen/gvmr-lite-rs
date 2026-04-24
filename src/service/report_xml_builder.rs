use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportXmlBuildError {
    #[error("report_json must be an object")]
    RootMustBeObject,
}

pub fn build_report_xml(report_json: &Value) -> Result<String, ReportXmlBuildError> {
    let data = report_json
        .as_object()
        .ok_or(ReportXmlBuildError::RootMustBeObject)?;

    let payload = data
        .get("report")
        .and_then(Value::as_object)
        .unwrap_or(data);

    let mut out = String::from(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    out.push_str("<report>");

    write_object_content(&mut out, payload);

    out.push_str("</report>");

    Ok(out)
}

fn write_object_content(out: &mut String, object: &Map<String, Value>) {
    for (key, value) in ordered_items("report", object) {
        if is_special_key(key) || key.starts_with('@') {
            continue;
        }

        write_node(out, key, value);
    }
}

fn write_node(out: &mut String, tag: &str, value: &Value) {
    if value.is_null() {
        return;
    }

    if let Some(items) = value.as_array() {
        for item in items {
            write_node(out, tag, item);
        }
        return;
    }

    out.push('<');
    out.push_str(tag);

    if let Some(object) = value.as_object() {
        write_attrs(out, object);
    }

    out.push('>');

    match value {
        Value::Object(object) => {
            if let Some(text) = object.get("#text") {
                write_text(out, text);
            }

            for (child_key, child_value) in ordered_items(tag, object) {
                if is_special_key(child_key) || child_key.starts_with('@') {
                    continue;
                }

                write_node(out, child_key, child_value);
            }
        }
        scalar => write_text(out, scalar),
    }

    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

fn write_attrs(out: &mut String, object: &Map<String, Value>) {
    for (key, value) in object {
        if !key.starts_with('@') || key == "@attrs" || value.is_null() {
            continue;
        }

        out.push(' ');
        out.push_str(&key[1..]);
        out.push_str("=\"");
        out.push_str(&escape_attr(&scalar_to_text(value)));
        out.push('"');
    }

    if let Some(attrs) = object.get("@attrs").and_then(Value::as_object) {
        for (key, value) in attrs {
            if value.is_null() {
                continue;
            }

            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            out.push_str(&escape_attr(&scalar_to_text(value)));
            out.push('"');
        }
    }
}

fn write_text(out: &mut String, value: &Value) {
    out.push_str(&escape_text(&scalar_to_text(value)));
}

fn scalar_to_text(value: &Value) -> String {
    match value {
        Value::String(s) => sanitize_text(s),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => sanitize_text(&other.to_string()),
    }
}

fn ordered_items<'a>(tag: &str, object: &'a Map<String, Value>) -> Vec<(&'a String, &'a Value)> {
    let mut items: Vec<_> = object
        .iter()
        .filter(|(key, _)| !is_special_key(key) && !key.starts_with('@'))
        .collect();

    if tag == "result" {
        items.sort_by_key(|(key, _)| result_key_rank(key));
    }

    items
}

fn result_key_rank(key: &str) -> usize {
    RESULT_KEY_ORDER
        .iter()
        .position(|candidate| *candidate == key)
        .unwrap_or(10_000)
}

fn is_special_key(key: &str) -> bool {
    matches!(key, "@attrs" | "#text")
}

fn sanitize_text(input: &str) -> String {
    input
        .chars()
        .filter(|ch| {
            !matches!(
                *ch as u32,
                0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f
            )
        })
        .collect()
}

fn escape_text(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(input: &str) -> String {
    escape_text(input).replace('"', "&quot;")
}

const RESULT_KEY_ORDER: &[&str] = &[
    "name",
    "owner",
    "modification_time",
    "comment",
    "creation_time",
    "host",
    "port",
    "nvt",
    "scan_nvt_version",
    "threat",
    "severity",
    "qod",
    "description",
    "original_threat",
    "original_severity",
    "compliance",
    "detection",
];
