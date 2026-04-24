use serde_json::Value;

pub fn inject_graph_gen_fields(report_json: &Value) -> Result<Value, String> {
    let mut data = report_json.clone();

    let Some(root) = data.as_object_mut() else {
        return Err("Expected dict-like report_json".to_string());
    };

    let report = match root.get_mut("report") {
        Some(Value::Object(report)) => report,
        _ => root,
    };

    let Some(results) = report.get_mut("results").and_then(Value::as_object_mut) else {
        return Ok(data);
    };

    let Some(result_value) = results.get_mut("result") else {
        return Ok(data);
    };

    if result_value.is_object() {
        let original = result_value.take();
        *result_value = Value::Array(vec![original]);
    }

    let Some(Value::Array(result_list)) = results.get_mut("result") else {
        return Ok(data);
    };

    for result in result_list {
        let Some(result_obj) = result.as_object_mut() else {
            continue;
        };

        if let Some(nvt) = result_obj.get_mut("nvt").and_then(Value::as_object_mut) {
            if !nvt.contains_key("@oid")
                && let Some(oid_value) = nvt.get("oid").cloned()
                && !is_falsey(&oid_value)
            {
                nvt.insert("@oid".to_string(), oid_value);
                nvt.remove("oid");
            }

            let ref_values = nvt.get("refs").map(collect_ref_values).unwrap_or_default();

            let cves = extract_cves_from_values(&ref_values);
            let existing_cve = nvt.get("cve").cloned();

            let cve_missing_or_empty = existing_cve
                .as_ref()
                .map(|v| value_to_string(v).trim().is_empty())
                .unwrap_or(true);

            if cve_missing_or_empty && !cves.is_empty() {
                nvt.insert("cve".to_string(), Value::String(cves.join(", ")));
            }

            if let Some(Value::Array(items)) = existing_cve {
                let joined = items
                    .iter()
                    .map(value_to_string)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");

                nvt.insert("cve".to_string(), Value::String(joined));
            }
        }

        match result_obj.get_mut("host") {
            None | Some(Value::Null) => {
                result_obj.insert("host".to_string(), Value::String(String::new()));
            }
            Some(Value::Object(host)) if !host.contains_key("#text") => {
                host.insert("#text".to_string(), Value::String(String::new()));
            }
            _ => {}
        }
    }

    Ok(data)
}

fn collect_ref_values(refs: &Value) -> Vec<Value> {
    match refs {
        Value::Null => Vec::new(),
        Value::Object(map) => {
            let mut out = Vec::new();

            if let Some(xref) = map.get("xref") {
                out.extend(as_list(xref));
            }

            for item in map.get("ref").map(as_list).unwrap_or_default() {
                match item {
                    Value::Object(ref_obj) => {
                        if let Some(id) = ref_obj.get("@id") {
                            out.push(id.clone());
                        }
                    }
                    other => out.push(other),
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
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
        .filter(|word| is_cve(word))
        .map(|word| word.to_ascii_uppercase())
        .collect()
}

fn is_cve(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();

    parts.len() == 3
        && parts[0].eq_ignore_ascii_case("CVE")
        && parts[1].len() == 4
        && parts[1].chars().all(|ch| ch.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|ch| ch.is_ascii_digit())
}

fn is_falsey(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        _ => false,
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
