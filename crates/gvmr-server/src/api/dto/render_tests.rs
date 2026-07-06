use serde_json::json;

use super::{
    FilterKeyword, Filters, HostValue, OciImage, RenderRequest, ReportResult, ResultHost, Scalar,
    Task, TaskScopeObject,
};

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
fn task_deserializes_target_scope_objects() {
    let task: Task = serde_json::from_value(json!({
        "id": "task-1",
        "name": "Container scan",
        "target": {
            "id": "target-1",
            "trash": 0,
            "name": "normal-target",
            "comment": ""
        },
        "oci_image_target": {
            "id": "oci-target-1",
            "trash": 0,
            "name": "euleros-ex",
            "comment": ""
        },
        "agent_group": {
            "id": "agent-group-1",
            "trash": 0,
            "name": "agent-group-1-1",
            "comment": ""
        }
    }))
    .unwrap();

    assert_eq!(task.id.as_deref(), Some("task-1"));
    assert_eq!(task.name.as_deref(), Some("Container scan"));

    let target = task.target.as_ref().unwrap();
    assert_eq!(target.id.as_deref(), Some("target-1"));
    assert_eq!(target.name.as_deref(), Some("normal-target"));
    assert_eq!(target.trash.as_ref(), Some(&json!(0)));

    let oci_image_target = task.oci_image_target.as_ref().unwrap();
    assert_eq!(oci_image_target.id.as_deref(), Some("oci-target-1"));
    assert_eq!(oci_image_target.name.as_deref(), Some("euleros-ex"));
    assert_eq!(oci_image_target.trash.as_ref(), Some(&json!(0)));

    let agent_group = task.agent_group.as_ref().unwrap();
    assert_eq!(agent_group.id.as_deref(), Some("agent-group-1"));
    assert_eq!(agent_group.name.as_deref(), Some("agent-group-1-1"));
    assert_eq!(agent_group.trash.as_ref(), Some(&json!(0)));
}

#[test]
fn task_scope_object_preserves_extra_fields() {
    let scope: TaskScopeObject = serde_json::from_value(json!({
        "id": "scope-1",
        "trash": 0,
        "name": "scope-name",
        "comment": "",
        "custom_field": "kept"
    }))
    .unwrap();

    assert_eq!(scope.id.as_deref(), Some("scope-1"));
    assert_eq!(scope.name.as_deref(), Some("scope-name"));
    assert_eq!(scope.trash.as_ref(), Some(&json!(0)));
    assert_eq!(scope.extra.get("custom_field"), Some(&json!("kept")));
}

#[test]
fn oci_image_deserializes_known_fields_and_extra_fields() {
    let image: OciImage = serde_json::from_value(json!({
        "name": "oci://registry.example.com/euleros/cspmtcenter:25.0.7",
        "digest": "sha256:abc",
        "registry": "registry.example.com",
        "path": "euleros",
        "short_name": "cspmtcenter:25.0.7",
        "architecture": "amd64"
    }))
    .unwrap();

    assert_eq!(
        image.name.as_deref(),
        Some("oci://registry.example.com/euleros/cspmtcenter:25.0.7")
    );
    assert_eq!(image.digest.as_deref(), Some("sha256:abc"));
    assert_eq!(image.registry.as_deref(), Some("registry.example.com"));
    assert_eq!(image.path.as_deref(), Some("euleros"));
    assert_eq!(image.short_name.as_deref(), Some("cspmtcenter:25.0.7"));
    assert_eq!(image.extra.get("architecture"), Some(&json!("amd64")));
}

#[test]
fn report_result_allows_missing_host() {
    let result: ReportResult = serde_json::from_value(json!({
        "name": "finding without host",
        "threat": "High",
        "severity": 8.0
    }))
    .unwrap();

    assert_eq!(result.name.as_deref(), Some("finding without host"));
    assert!(result.host.is_none());
    assert_eq!(result.threat.as_deref(), Some("High"));
    assert_eq!(result.severity.as_ref(), Some(&json!(8.0)));
}

#[test]
fn report_result_deserializes_oci_image() {
    let result: ReportResult = serde_json::from_value(json!({
        "@attrs": {
            "id": "result-1"
        },
        "name": "container finding",
        "host": {
            "#text": "sha256:abc",
            "hostname": "oci://registry.example.com/euleros/cspmtcenter:25.0.7"
        },
        "port": "general/tcp",
        "threat": "High",
        "severity": 8.0,
        "oci_image": {
            "name": "oci://registry.example.com/euleros/cspmtcenter:25.0.7",
            "digest": "sha256:abc",
            "registry": "registry.example.com",
            "path": "euleros",
            "short_name": "cspmtcenter:25.0.7"
        }
    }))
    .unwrap();

    assert_eq!(
        result.attrs.as_ref().unwrap().get("id"),
        Some(&json!("result-1"))
    );
    assert_eq!(result.name.as_deref(), Some("container finding"));
    assert_eq!(result.port.as_deref(), Some("general/tcp"));
    assert_eq!(result.threat.as_deref(), Some("High"));
    assert_eq!(result.severity.as_ref(), Some(&json!(8.0)));

    match result.host.unwrap() {
        HostValue::Object(host) => {
            assert_eq!(host.text.as_deref(), Some("sha256:abc"));
            assert_eq!(
                host.hostname.as_deref(),
                Some("oci://registry.example.com/euleros/cspmtcenter:25.0.7")
            );
        }
        _ => panic!("expected HostValue::Object"),
    }

    let image = result.oci_image.as_ref().unwrap();
    assert_eq!(
        image.name.as_deref(),
        Some("oci://registry.example.com/euleros/cspmtcenter:25.0.7")
    );
    assert_eq!(image.digest.as_deref(), Some("sha256:abc"));
    assert_eq!(image.registry.as_deref(), Some("registry.example.com"));
    assert_eq!(image.path.as_deref(), Some("euleros"));
    assert_eq!(image.short_name.as_deref(), Some("cspmtcenter:25.0.7"));
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

#[test]
fn render_request_report_json_value_serializes_oci_image_target_and_oci_image_result() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {
            "@attrs": {
                "id": "report-1"
            },
            "task": {
                "id": "task-1",
                "name": "Container scan",
                "oci_image_target": {
                    "id": "oci-target-1",
                    "trash": 0,
                    "name": "euleros-ex",
                    "comment": ""
                }
            },
            "results": {
                "result": [
                    {
                        "@attrs": {
                            "id": "result-1"
                        },
                        "name": "container finding",
                        "host": {
                            "#text": "sha256:abc",
                            "hostname": "oci://registry.example.com/euleros/cspmtcenter:25.0.7"
                        },
                        "port": "general/tcp",
                        "threat": "High",
                        "severity": 8.0,
                        "oci_image": {
                            "name": "oci://registry.example.com/euleros/cspmtcenter:25.0.7",
                            "digest": "sha256:abc",
                            "registry": "registry.example.com",
                            "path": "euleros",
                            "short_name": "cspmtcenter:25.0.7"
                        }
                    }
                ]
            },
            "result_count": {
                "filtered": 1
            }
        }
    }))
    .unwrap();

    let value = request.report_json_value();

    assert_eq!(value["@attrs"]["id"], json!("report-1"));
    assert_eq!(
        value["task"]["oci_image_target"]["id"],
        json!("oci-target-1")
    );
    assert_eq!(
        value["task"]["oci_image_target"]["name"],
        json!("euleros-ex")
    );

    let result = &value["results"]["result"][0];

    assert_eq!(result["@attrs"]["id"], json!("result-1"));
    assert_eq!(result["host"]["#text"], json!("sha256:abc"));
    assert_eq!(
        result["host"]["hostname"],
        json!("oci://registry.example.com/euleros/cspmtcenter:25.0.7")
    );
    assert_eq!(result["oci_image"]["digest"], json!("sha256:abc"));
    assert_eq!(
        result["oci_image"]["short_name"],
        json!("cspmtcenter:25.0.7")
    );
}

#[test]
fn render_request_report_json_value_serializes_agent_group() {
    let request: RenderRequest = serde_json::from_value(json!({
        "format_id": "format-1",
        "report_json": {
            "task": {
                "id": "task-1",
                "name": "Agent scan",
                "agent_group": {
                    "id": "agent-group-1",
                    "trash": 0,
                    "name": "agent-group-1-1",
                    "comment": ""
                }
            }
        }
    }))
    .unwrap();

    let value = request.report_json_value();

    assert_eq!(value["task"]["agent_group"]["id"], json!("agent-group-1"));
    assert_eq!(
        value["task"]["agent_group"]["name"],
        json!("agent-group-1-1")
    );
    assert_eq!(value["task"]["agent_group"]["trash"], json!(0));
}
