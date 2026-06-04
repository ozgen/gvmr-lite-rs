use super::RenderAuditXmlRequest;
use serde_json::{Map, json};

fn valid_request() -> RenderAuditXmlRequest {
    RenderAuditXmlRequest {
        format_id: "compliance-pdf".to_string(),
        report_xml: "<report/>".to_string(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 300,
    }
}

#[test]
fn validate_accepts_valid_request() {
    let request = valid_request();

    assert_eq!(request.validate(), Ok(()));
}

#[test]
fn validate_rejects_empty_format_id() {
    let mut request = valid_request();
    request.format_id = String::new();

    assert_eq!(
        request.validate(),
        Err("format_id must not be empty".to_string())
    );
}

#[test]
fn validate_rejects_whitespace_only_format_id() {
    let mut request = valid_request();
    request.format_id = " \n\t ".to_string();

    assert_eq!(
        request.validate(),
        Err("format_id must not be empty".to_string())
    );
}

#[test]
fn validate_rejects_empty_report_xml() {
    let mut request = valid_request();
    request.report_xml = String::new();

    assert_eq!(
        request.validate(),
        Err("report_xml must not be empty".to_string())
    );
}

#[test]
fn validate_rejects_whitespace_only_report_xml() {
    let mut request = valid_request();
    request.report_xml = " \n\t ".to_string();

    assert_eq!(
        request.validate(),
        Err("report_xml must not be empty".to_string())
    );
}

#[test]
fn validate_accepts_timeout_lower_boundary() {
    let mut request = valid_request();
    request.timeout_seconds = 1;

    assert_eq!(request.validate(), Ok(()));
}

#[test]
fn validate_accepts_timeout_upper_boundary() {
    let mut request = valid_request();
    request.timeout_seconds = 40001;

    assert_eq!(request.validate(), Ok(()));
}

#[test]
fn validate_rejects_timeout_below_lower_boundary() {
    let mut request = valid_request();
    request.timeout_seconds = 0;

    assert_eq!(
        request.validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn validate_rejects_timeout_above_upper_boundary() {
    let mut request = valid_request();
    request.timeout_seconds = 40002;

    assert_eq!(
        request.validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn validate_checks_format_id_before_report_xml() {
    let request = RenderAuditXmlRequest {
        format_id: String::new(),
        report_xml: String::new(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 0,
    };

    assert_eq!(
        request.validate(),
        Err("format_id must not be empty".to_string())
    );
}

#[test]
fn validate_checks_report_xml_before_timeout() {
    let request = RenderAuditXmlRequest {
        format_id: "compliance-pdf".to_string(),
        report_xml: String::new(),
        params: Map::new(),
        output_name: None,
        timeout_seconds: 0,
    };

    assert_eq!(
        request.validate(),
        Err("report_xml must not be empty".to_string())
    );
}

#[test]
fn deserialize_uses_default_params_when_missing() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "output_name": null,
        "timeout_seconds": 60
    }))
    .expect("request should deserialize");

    assert!(request.params.is_empty());
    assert_eq!(request.timeout_seconds, 60);
}

#[test]
fn deserialize_uses_default_timeout_when_missing() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "params": {},
        "output_name": null
    }))
    .expect("request should deserialize");

    assert_eq!(request.timeout_seconds, 300);
}

#[test]
fn deserialize_preserves_params() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "params": {
            "language": "en",
            "compact": true,
            "page_limit": 100
        },
        "output_name": null
    }))
    .expect("request should deserialize");

    assert_eq!(request.params.get("language"), Some(&json!("en")));
    assert_eq!(request.params.get("compact"), Some(&json!(true)));
    assert_eq!(request.params.get("page_limit"), Some(&json!(100)));
}

#[test]
fn deserialize_preserves_output_name() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "params": {},
        "output_name": "compliance-report.pdf"
    }))
    .expect("request should deserialize");

    assert_eq!(
        request.output_name.as_deref(),
        Some("compliance-report.pdf")
    );
}

#[test]
fn deserialize_allows_null_output_name() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "params": {},
        "output_name": null
    }))
    .expect("request should deserialize");

    assert_eq!(request.output_name, None);
}

#[test]
fn deserialize_uses_none_when_output_name_is_missing() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "params": {}
    }))
    .expect("missing output_name should deserialize as None");

    assert_eq!(request.output_name, None);
}

#[test]
fn deserialize_fails_when_required_format_id_is_missing() {
    let err = serde_json::from_value::<RenderAuditXmlRequest>(json!({
        "report_xml": "<report/>",
        "params": {},
        "output_name": null
    }))
    .expect_err("missing format_id should fail");

    assert!(err.to_string().contains("missing field `format_id`"));
}

#[test]
fn deserialize_fails_when_required_report_xml_is_missing() {
    let err = serde_json::from_value::<RenderAuditXmlRequest>(json!({
        "format_id": "compliance-pdf",
        "params": {},
        "output_name": null
    }))
    .expect_err("missing report_xml should fail");

    assert!(err.to_string().contains("missing field `report_xml`"));
}

#[test]
fn serialize_includes_all_fields() {
    let request = RenderAuditXmlRequest {
        format_id: "compliance-pdf".to_string(),
        report_xml: "<report/>".to_string(),
        params: Map::from_iter([
            ("language".to_string(), json!("en")),
            ("compact".to_string(), json!(true)),
        ]),
        output_name: Some("compliance-report.pdf".to_string()),
        timeout_seconds: 60,
    };

    let value = serde_json::to_value(request).expect("request should serialize");

    assert_eq!(value["format_id"], json!("compliance-pdf"));
    assert_eq!(value["report_xml"], json!("<report/>"));
    assert_eq!(value["params"]["language"], json!("en"));
    assert_eq!(value["params"]["compact"], json!(true));
    assert_eq!(value["output_name"], json!("compliance-report.pdf"));
    assert_eq!(value["timeout_seconds"], json!(60));
}
