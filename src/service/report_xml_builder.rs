use serde_json::{Map, Value, json};
use thiserror::Error;

const SPECIAL_KEYS: &[&str] = &["@attrs", "#text"];
const FORCE_TEXT_TAGS: &[&str] = &["description", "term"];

const REPORT_KEY_ORDER: &[&str] = &[
    "timezone",
    "scan_start",
    "scan_end",
    "task",
    "target",
    "filters",
    "result_count",
    "results",
    "host",
    "hosts",
    "ports",
    "severity",
    "timestamp",
];

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

const HOST_KEY_ORDER: &[&str] = &[
    "ip",
    "asset",
    "start",
    "end",
    "port_count",
    "result_count",
    "detail",
];

#[derive(Debug, Error)]
pub enum ReportXmlBuildError {
    #[error("report_json must be an object")]
    RootMustBeObject,
}

pub fn build_report_xml(report_json: &Value) -> Result<String, ReportXmlBuildError> {
    let data = report_json
        .as_object()
        .ok_or(ReportXmlBuildError::RootMustBeObject)?;

    let mut payload = data
        .get("report")
        .cloned()
        .unwrap_or_else(|| report_json.clone());

    strip_nulls(&mut payload);
    normalize_for_graph_gen(&mut payload);

    let mut out = String::from(r#"<?xml version="1.0" encoding="utf-8"?>"#);

    write_node(&mut out, "report", &payload);

    Ok(out)
}

fn normalize_for_graph_gen(payload: &mut Value) {
    let Some(payload) = payload.as_object_mut() else {
        return;
    };

    normalize_results(payload);
    normalize_ports(payload);
    normalize_filters(payload);
}

fn normalize_results(payload: &mut Map<String, Value>) {
    let Some(results) = payload.get_mut("results").and_then(Value::as_object_mut) else {
        return;
    };

    let attrs = ensure_object_field(results, "@attrs");

    let start = attrs.get("start").cloned();
    let normalized_start = match start {
        None | Some(Value::Null) => 1,
        Some(Value::String(s)) if s.trim().is_empty() => 1,
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(1),
        Some(Value::Number(n)) => n.as_i64().unwrap_or(1),
        _ => 1,
    };

    attrs.insert("start".to_string(), json!(normalized_start));

    let Some(result_value) = results.get_mut("result") else {
        return;
    };

    if result_value.is_object() {
        let original = result_value.take();
        *result_value = Value::Array(vec![original]);
    }

    let Some(Value::Array(result_list)) = results.get_mut("result") else {
        return;
    };

    for result in result_list {
        let Some(result) = result.as_object_mut() else {
            continue;
        };

        let should_default_port = match result.get("port") {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.trim().is_empty(),
            _ => false,
        };

        if should_default_port {
            result.insert("port".to_string(), Value::String("general/tcp".to_string()));
        }

        match result.get_mut("host") {
            None | Some(Value::Null) => {
                result.insert("host".to_string(), Value::String(String::new()));
            }
            Some(Value::Object(host)) if !host.contains_key("#text") => {
                host.insert("#text".to_string(), Value::String(String::new()));
            }
            _ => {}
        }

        match result.get_mut("threat") {
            None | Some(Value::Null) => {
                result.insert("threat".to_string(), Value::String("Low".to_string()));
            }
            Some(Value::String(s)) => {
                let normalized = s.trim().to_ascii_lowercase();
                if normalized.is_empty() || normalized == "info" || normalized == "informational" {
                    *s = "Low".to_string();
                }
            }
            _ => {}
        }

        if let Some(nvt) = result.get_mut("nvt").and_then(Value::as_object_mut) {
            normalize_nvt_refs(nvt);
        }
    }
}

fn normalize_ports(payload: &mut Map<String, Value>) {
    let Some(ports) = payload.get_mut("ports").and_then(Value::as_object_mut) else {
        return;
    };

    let attrs = ensure_object_field(ports, "@attrs");

    if matches!(attrs.get("start"), None | Some(Value::Null))
        || attrs.get("start").and_then(Value::as_str) == Some("")
    {
        attrs.insert("start".to_string(), json!(1));
    }
}

fn normalize_filters(payload: &mut Map<String, Value>) {
    let Some(filters) = payload.get_mut("filters").and_then(Value::as_object_mut) else {
        return;
    };

    if !filters.contains_key("term")
        && let Some(phrase) = filters.get("phrase").cloned()
    {
        filters.insert("term".to_string(), phrase);
    }
}

fn normalize_nvt_refs(nvt: &mut Map<String, Value>) {
    let Some(refs) = nvt.get_mut("refs").and_then(Value::as_object_mut) else {
        return;
    };

    if refs.contains_key("ref") {
        let Some(ref_items) = refs.get_mut("ref") else {
            return;
        };

        if let Value::Array(items) = ref_items {
            for item in items {
                normalize_ref_item(item);
            }
        } else {
            let mut item = ref_items.take();
            normalize_ref_item(&mut item);
            *ref_items = Value::Array(vec![item]);
        }

        return;
    }

    if let Some(xrefs) = refs.remove("xref") {
        let items = match xrefs {
            Value::Array(items) => items
                .into_iter()
                .map(|x| json!({ "@id": x }))
                .collect::<Vec<_>>(),
            other => vec![json!({ "@id": other })],
        };

        refs.insert("ref".to_string(), Value::Array(items));
    }
}

fn normalize_ref_item(item: &mut Value) {
    let Some(object) = item.as_object_mut() else {
        let original = item.take();
        *item = json!({ "@id": original });
        return;
    };

    if !object.contains_key("@type")
        && let Some(value) = object.remove("type")
    {
        if value.is_object() || value.is_array() {
            object.insert("type".to_string(), value);
        } else {
            object.insert("@type".to_string(), value);
        }
    }

    if !object.contains_key("@id")
        && let Some(value) = object.remove("id")
    {
        if value.is_object() || value.is_array() {
            object.insert("id".to_string(), value);
        } else {
            object.insert("@id".to_string(), value);
        }
    }
}

fn write_node(out: &mut String, tag: &str, value: &Value) {
    if value.is_null() {
        return;
    }

    if FORCE_TEXT_TAGS.contains(&tag) {
        out.push('<');
        out.push_str(tag);
        out.push('>');
        out.push_str(&escape_text(&force_text(value)));
        out.push_str("</");
        out.push_str(tag);
        out.push('>');
        return;
    }

    if let Value::Array(items) = value {
        for item in items {
            write_node(out, tag, item);
        }
        return;
    }

    out.push('<');
    out.push_str(tag);

    if let Value::Object(object) = value {
        write_attrs(out, object);
        if tag == "nvt" {
            write_nvt_oid_attr_if_missing(out, object);
        }
    }

    out.push('>');

    match value {
        Value::Object(object) => {
            if let Some(text) = object.get("#text") {
                write_text(out, text);
            }

            for (key, child) in ordered_items(tag, object) {
                if tag == "nvt" && key == "oid" {
                    continue;
                }

                write_node(out, key, child);
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

fn write_nvt_oid_attr_if_missing(out: &mut String, object: &Map<String, Value>) {
    let already_written = object.contains_key("@oid")
        || object
            .get("@attrs")
            .and_then(Value::as_object)
            .is_some_and(|attrs| attrs.contains_key("oid"));

    if already_written {
        return;
    }

    let Some(oid) = object.get("oid") else {
        return;
    };

    if oid.is_object() || oid.is_array() || oid.is_null() {
        return;
    }

    out.push_str(" oid=\"");
    out.push_str(&escape_attr(&scalar_to_text(oid)));
    out.push('"');
}

fn ordered_items<'a>(tag: &str, object: &'a Map<String, Value>) -> Vec<(&'a String, &'a Value)> {
    let mut items = object
        .iter()
        .filter(|(key, _)| !is_special_key(key) && !key.starts_with('@'))
        .collect::<Vec<_>>();

    if tag == "report" {
        items.sort_by_key(|(key, _)| key_rank(key, REPORT_KEY_ORDER));
    } else if tag == "result" {
        items.sort_by_key(|(key, _)| key_rank(key, RESULT_KEY_ORDER));
    } else if tag == "host" {
        items.sort_by_key(|(key, _)| key_rank(key, HOST_KEY_ORDER));
    }

    items
}

fn is_special_key(key: &str) -> bool {
    SPECIAL_KEYS.contains(&key)
}

fn ensure_object_field<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
) -> &'a mut Map<String, Value> {
    let value = object
        .entry(key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));

    if !value.is_object() {
        *value = Value::Object(Map::new());
    }

    value.as_object_mut().expect("object was just inserted")
}

fn write_text(out: &mut String, value: &Value) {
    out.push_str(&escape_text(&scalar_to_text(value)));
}

fn force_text(value: &Value) -> String {
    if let Value::Object(object) = value {
        if let Some(text) = object.get("#text") {
            return scalar_to_text(text);
        }

        return serde_json::to_string(object).unwrap_or_default();
    }

    if let Value::Array(items) = value {
        return items
            .iter()
            .map(|item| {
                item.as_object()
                    .and_then(|object| object.get("#text"))
                    .map(scalar_to_text)
                    .unwrap_or_else(|| scalar_to_text(item))
            })
            .collect::<Vec<_>>()
            .join("\n");
    }

    scalar_to_text(value)
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

fn key_rank(key: &str, order: &[&str]) -> usize {
    order
        .iter()
        .position(|candidate| *candidate == key)
        .unwrap_or(10_000)
}

fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                strip_nulls(child);
            }

            map.retain(|_, value| !value.is_null());
        }
        Value::Array(items) => {
            for item in items {
                strip_nulls(item);
            }
        }
        _ => {}
    }
}
