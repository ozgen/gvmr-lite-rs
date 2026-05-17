use serde_json::json;

use super::{FilterKeyword, Filters, HostValue, RenderRequest, ResultHost, Scalar};

#[test]
fn scalar_deserializes_string() {
    let value: Scalar = serde_json::from_value(json!("hello")).unwrap();

    match value {
        Scalar::String(value) => assert_eq!(value, "hello"),
        _ => panic!("expected Scalar::String"),
    }
}

#[test]
fn scalar_deserializes_integer() {
    let value: Scalar = serde_json::from_value(json!(42)).unwrap();

    match value {
        Scalar::Integer(value) => assert_eq!(value, 42),
        _ => panic!("expected Scalar::Integer"),
    }
}

#[test]
fn scalar_deserializes_float() {
    let value: Scalar = serde_json::from_value(json!(4.2)).unwrap();

    match value {
        Scalar::Float(value) => assert_eq!(value, 4.2),
        _ => panic!("expected Scalar::Float"),
    }
}

#[test]
fn scalar_deserializes_bool() {
    let value: Scalar = serde_json::from_value(json!(true)).unwrap();

    match value {
        Scalar::Bool(value) => assert!(value),
        _ => panic!("expected Scalar::Bool"),
    }
}

#[test]
fn filter_keyword_defaults_relation_to_equals() {
    let keyword: FilterKeyword = serde_json::from_value(json!({
        "column": "severity",
        "value": "high"
    }))
    .unwrap();

    assert_eq!(keyword.column, "severity");
    assert_eq!(keyword.relation, "=");

    match keyword.value {
        Scalar::String(value) => assert_eq!(value, "high"),
        _ => panic!("expected Scalar::String"),
    }
}

#[test]
fn filter_keyword_preserves_extra_fields() {
    let keyword: FilterKeyword = serde_json::from_value(json!({
        "column": "severity",
        "relation": ">",
        "value": 5,
        "custom_field": "kept"
    }))
    .unwrap();

    assert_eq!(keyword.column, "severity");
    assert_eq!(keyword.relation, ">");
    assert_eq!(keyword.extra.get("custom_field"), Some(&json!("kept")));
}

#[test]
fn filters_default_missing_fields() {
    let filters: Filters = serde_json::from_value(json!({})).unwrap();

    assert_eq!(filters.term, "");
    assert!(filters.phrase.is_none());
    assert!(filters.filter.is_empty());
    assert!(filters.keywords.keyword.is_empty());
    assert!(filters.extra.is_empty());
}

#[test]
fn filters_deserializes_attrs_and_extra_fields() {
    let filters: Filters = serde_json::from_value(json!({
        "@attrs": {
            "id": "filter-1"
        },
        "term": "severity > 5",
        "unknown": "kept"
    }))
    .unwrap();

    assert_eq!(filters.term, "severity > 5");
    assert_eq!(
        filters.attrs.as_ref().unwrap().get("id"),
        Some(&json!("filter-1"))
    );
    assert_eq!(filters.extra.get("unknown"), Some(&json!("kept")));
}

#[test]
fn host_value_deserializes_string() {
    let host: HostValue = serde_json::from_value(json!("192.168.1.10")).unwrap();

    match host {
        HostValue::String(value) => assert_eq!(value, "192.168.1.10"),
        _ => panic!("expected HostValue::String"),
    }
}

#[test]
fn host_value_deserializes_object() {
    let host: HostValue = serde_json::from_value(json!({
        "#text": "192.168.1.10",
        "hostname": "example.local",
        "custom": "kept"
    }))
    .unwrap();

    match host {
        HostValue::Object(ResultHost {
            text,
            hostname,
            extra,
            ..
        }) => {
            assert_eq!(text.as_deref(), Some("192.168.1.10"));
            assert_eq!(hostname.as_deref(), Some("example.local"));
            assert_eq!(extra.get("custom"), Some(&json!("kept")));
        }
        _ => panic!("expected HostValue::Object"),
    }
}

#[test]
fn render_request_defaults_params_and_timeout_seconds() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {}
    }))
    .unwrap();

    assert_eq!(request.format_id, "format-1");
    assert!(request.params.is_empty());
    assert!(request.output_name.is_none());
    assert_eq!(request.timeout_seconds, 300);
}

#[test]
fn render_request_validate_accepts_valid_timeout() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {},
        "timeout_seconds": 40001
    }))
    .unwrap();

    assert!(request.validate().is_ok());
}

#[test]
fn render_request_validate_rejects_zero_timeout() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {},
        "timeout_seconds": 0
    }))
    .unwrap();

    assert_eq!(
        request.validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn render_request_validate_rejects_timeout_above_limit() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {},
        "timeout_seconds": 40002
    }))
    .unwrap();

    assert_eq!(
        request.validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn render_request_report_json_value_serializes_report_json() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {
            "@attrs": {
                "id": "report-1"
            },
            "scan_run_status": "Done",
            "hosts": {
                "count": 2
            },
            "custom_field": "kept"
        }
    }))
    .unwrap();

    let value = request.report_json_value();

    assert_eq!(value["@attrs"]["id"], json!("report-1"));
    assert_eq!(value["scan_run_status"], json!("Done"));
    assert_eq!(value["hosts"]["count"], json!(2));
    assert_eq!(value["custom_field"], json!("kept"));
}
