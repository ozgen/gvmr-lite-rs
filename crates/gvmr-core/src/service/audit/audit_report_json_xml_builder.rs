use serde_json::{Map, Value};

use crate::service::report_renderer::RenderError;

pub fn build_audit_report_xml_from_json(report_json: &Value) -> Result<String, RenderError> {
    let mut value = report_json.clone();

    strip_nulls(&mut value);

    let inner_report = extract_inner_report_json(value)?;

    let mut out = String::from(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    write_node(&mut out, "report", &inner_report);

    Ok(out)
}

fn extract_inner_report_json(value: Value) -> Result<Value, RenderError> {
    let Value::Object(mut object) = value else {
        return Err(RenderError::BuildXml(
            "audit report_json must be an object".to_string(),
        ));
    };

    if let Some(inner_report) = object.remove("report") {
        return Ok(inner_report);
    }

    Ok(Value::Object(object))
}

fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());

            for value in object.values_mut() {
                strip_nulls(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                strip_nulls(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn write_node(out: &mut String, tag: &str, value: &Value) {
    match value {
        Value::Null => {}

        Value::Object(object) => {
            write_object_node(out, tag, object);
        }

        Value::Array(values) => {
            for item in values {
                write_node(out, tag, item);
            }
        }

        Value::String(value) => {
            write_text_node(out, tag, value);
        }

        Value::Number(value) => {
            write_text_node(out, tag, &value.to_string());
        }

        Value::Bool(value) => {
            write_text_node(out, tag, &value.to_string());
        }
    }
}

fn write_object_node(out: &mut String, tag: &str, object: &Map<String, Value>) {
    out.push('<');
    out.push_str(tag);

    write_attrs(out, object);

    let text = object.get("#text").or_else(|| object.get("$text"));

    let has_children = object
        .iter()
        .any(|(key, value)| !is_special_key(key) && !value.is_null());

    if text.is_none() && !has_children {
        out.push_str("/>");
        return;
    }

    out.push('>');

    if let Some(text) = text {
        out.push_str(&escape_text(&value_to_string(text)));
    }

    for (key, value) in object {
        if is_special_key(key) {
            continue;
        }

        write_node(out, key, value);
    }

    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

fn write_attrs(out: &mut String, object: &Map<String, Value>) {
    if let Some(Value::Object(attrs)) = object.get("@attrs") {
        for (key, value) in attrs {
            write_attr(out, key, value);
        }
    }

    for (key, value) in object {
        if key == "@attrs" {
            continue;
        }

        let Some(attr_name) = key.strip_prefix('@') else {
            continue;
        };

        write_attr(out, attr_name, value);
    }
}

fn write_attr(out: &mut String, key: &str, value: &Value) {
    if value.is_null() {
        return;
    }

    out.push(' ');
    out.push_str(key);
    out.push_str("=\"");
    out.push_str(&escape_attr(&value_to_string(value)));
    out.push('"');
}

fn write_text_node(out: &mut String, tag: &str, text: &str) {
    out.push('<');
    out.push_str(tag);
    out.push('>');
    out.push_str(&escape_text(text));
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

fn is_special_key(key: &str) -> bool {
    key == "@attrs" || key.starts_with('@') || key == "#text" || key == "$text"
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(value: &str) -> String {
    escape_text(value).replace('"', "&quot;")
}

#[cfg(test)]
#[path = "audit_report_json_xml_builder_tests.rs"]
mod audit_report_json_xml_builder_tests;
