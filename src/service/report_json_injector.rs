use serde_json::{Map, Value};

pub fn inject_graph_gen_fields(report_json: &Value) -> Result<Value, String> {
    let mut data = report_json.clone();

    let Some(root) = data.as_object_mut() else {
        return Err("Expected object-like report_json".to_string());
    };

    let report = match root.get_mut("report") {
        Some(Value::Object(report)) => report,
        _ => root,
    };

    let Some(results) = report.get_mut("results").and_then(Value::as_object_mut) else {
        return Ok(data);
    };

    normalize_result_list(results);

    let Some(Value::Array(result_list)) = results.get_mut("result") else {
        return Ok(data);
    };

    for result in result_list {
        let Some(result_obj) = result.as_object_mut() else {
            continue;
        };

        inject_nvt_fields(result_obj);
        normalize_host(result_obj);
    }

    Ok(data)
}

fn normalize_result_list(results: &mut Map<String, Value>) {
    let Some(result) = results.get_mut("result") else {
        return;
    };

    if result.is_object() {
        let original = result.take();
        *result = Value::Array(vec![original]);
    }
}

fn inject_nvt_fields(result: &mut Map<String, Value>) {
    let Some(nvt) = result.get_mut("nvt").and_then(Value::as_object_mut) else {
        return;
    };

    if !nvt.contains_key("@oid")
        && let Some(oid) = nvt.remove("oid")
        && !oid.is_null()
    {
        nvt.insert("@oid".to_string(), oid);
    }

    let ref_values = nvt.get("refs").map(collect_ref_values).unwrap_or_default();

    let cves = extract_cves_from_values(&ref_values);

    let existing_cve = nvt.get("cve");

    let cve_missing_or_empty = match existing_cve {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        _ => false,
    };

    if cve_missing_or_empty && !cves.is_empty() {
        nvt.insert("cve".to_string(), Value::String(cves.join(", ")));
    } else if let Some(Value::Array(items)) = existing_cve {
        let joined = items
            .iter()
            .filter_map(value_to_non_empty_string)
            .collect::<Vec<_>>()
            .join(", ");

        nvt.insert("cve".to_string(), Value::String(joined));
    }
}

fn normalize_host(result: &mut Map<String, Value>) {
    match result.get_mut("host") {
        None | Some(Value::Null) => {
            result.insert("host".to_string(), Value::String(String::new()));
        }
        Some(Value::Object(host)) if !host.contains_key("#text") => {
            host.insert("#text".to_string(), Value::String(String::new()));
        }
        _ => {}
    }
}

fn collect_ref_values(refs: &Value) -> Vec<Value> {
    match refs {
        Value::Object(map) => {
            let mut out = Vec::new();

            if let Some(xref) = map.get("xref") {
                out.extend(as_list(xref));
            }

            if let Some(ref_value) = map.get("ref") {
                for item in as_list(ref_value) {
                    match item {
                        Value::Object(ref_obj) => {
                            if let Some(id) = ref_obj.get("@id") {
                                out.push(id.clone());
                            }
                        }
                        other => out.push(other),
                    }
                }
            }

            out
        }
        other => as_list(other),
    }
}

fn as_list(value: &Value) -> Vec<Value> {
    match value {
        Value::Null => Vec::new(),
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn extract_cves_from_values(values: &[Value]) -> Vec<String> {
    let mut found = Vec::new();

    for value in values {
        let text = value_to_string(value);

        for cve in extract_cves_from_text(&text) {
            if !found.contains(&cve) {
                found.push(cve);
            }
        }
    }

    found
}

fn extract_cves_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();

    for word in text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-') {
        if is_cve(word) {
            out.push(word.to_ascii_uppercase());
        }
    }

    out
}

fn is_cve(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();

    if parts.len() != 3 {
        return false;
    }

    if !parts[0].eq_ignore_ascii_case("CVE") {
        return false;
    }

    parts[1].len() == 4
        && parts[1].chars().all(|ch| ch.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|ch| ch.is_ascii_digit())
}

fn value_to_non_empty_string(value: &Value) -> Option<String> {
    let text = value_to_string(value);
    let trimmed = text.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
