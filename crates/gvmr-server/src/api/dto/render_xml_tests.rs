use super::RenderXmlRequest;
use serde_json::{Map, Value, json};

#[test]
fn deserialize_sets_default_timeout_seconds() {
    let raw = json!({
        "format_id": "fmt-1",
        "report_xml": "<report></report>"
    });

    let req: RenderXmlRequest = serde_json::from_value(raw).unwrap();

    assert_eq!(req.format_id, "fmt-1");
    assert_eq!(req.report_xml, "<report></report>");
    assert_eq!(req.timeout_seconds, 300);
    assert!(req.params.is_empty());
    assert_eq!(req.output_name, None);
}

#[test]
fn deserialize_accepts_all_fields() {
    let raw = json!({
        "format_id": "fmt-1",
        "report_xml": "<report></report>",
        "params": {
            "foo": "bar",
            "number": 123,
            "flag": true
        },
        "output_name": "custom.xml",
        "timeout_seconds": 60
    });

    let req: RenderXmlRequest = serde_json::from_value(raw).unwrap();

    assert_eq!(req.format_id, "fmt-1");
    assert_eq!(req.report_xml, "<report></report>");
    assert_eq!(req.output_name.as_deref(), Some("custom.xml"));
    assert_eq!(req.timeout_seconds, 60);

    assert_eq!(req.params.get("foo"), Some(&json!("bar")));
    assert_eq!(req.params.get("number"), Some(&json!(123)));
    assert_eq!(req.params.get("flag"), Some(&json!(true)));
}

#[test]
fn validate_accepts_minimum_timeout_seconds() {
    let req = test_request(1);

    let result = req.validate();

    assert_eq!(result, Ok(()));
}

#[test]
fn validate_accepts_maximum_timeout_seconds() {
    let req = test_request(40001);

    let result = req.validate();

    assert_eq!(result, Ok(()));
}

#[test]
fn validate_rejects_zero_timeout_seconds() {
    let req = test_request(0);

    let result = req.validate();

    assert_eq!(
        result,
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn validate_rejects_timeout_seconds_above_maximum() {
    let req = test_request(40002);

    let result = req.validate();

    assert_eq!(
        result,
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn serialize_preserves_request_fields() {
    let mut params = Map::new();
    params.insert("foo".to_string(), json!("bar"));
    params.insert("number".to_string(), json!(123));

    let req = RenderXmlRequest {
        format_id: "fmt-1".to_string(),
        report_xml: "<report></report>".to_string(),
        params,
        output_name: Some("custom.xml".to_string()),
        timeout_seconds: 30,
    };

    let value = serde_json::to_value(req).unwrap();

    assert_eq!(value["format_id"], json!("fmt-1"));
    assert_eq!(value["report_xml"], json!("<report></report>"));
    assert_eq!(value["params"]["foo"], json!("bar"));
    assert_eq!(value["params"]["number"], json!(123));
    assert_eq!(value["output_name"], json!("custom.xml"));
    assert_eq!(value["timeout_seconds"], json!(30));
}

fn test_request(timeout_seconds: u64) -> RenderXmlRequest {
    RenderXmlRequest {
        format_id: "fmt-1".to_string(),
        report_xml: "<report></report>".to_string(),
        params: Map::<String, Value>::new(),
        output_name: None,
        timeout_seconds,
    }
}
