use super::build_audit_report_xml_from_json;

use serde_json::json;

use crate::service::report_renderer::RenderError;

fn build(value: serde_json::Value) -> String {
    build_audit_report_xml_from_json(&value).expect("XML should be built")
}

#[test]
fn builds_xml_with_declaration_and_root_report() {
    let xml = build(json!({
        "report": {
            "scan_run_status": "Done"
        }
    }));

    assert!(xml.starts_with(r#"<?xml version="1.0" encoding="utf-8"?>"#));
    assert!(xml.contains("<report>"));
    assert!(xml.contains("<scan_run_status>Done</scan_run_status>"));
    assert!(xml.ends_with("</report>"));
}

#[test]
fn extracts_inner_report_when_report_field_exists() {
    let xml = build(json!({
        "@attrs": {
            "id": "outer-report"
        },
        "name": "Outer Report",
        "report": {
            "@attrs": {
                "id": "inner-report"
            },
            "scan_run_status": "Done"
        }
    }));

    assert!(xml.contains(r#"<report id="inner-report">"#));
    assert!(xml.contains("<scan_run_status>Done</scan_run_status>"));
    assert!(!xml.contains("outer-report"));
    assert!(!xml.contains("Outer Report"));
}

#[test]
fn uses_whole_object_when_report_field_is_missing() {
    let xml = build(json!({
        "@attrs": {
            "id": "report-1"
        },
        "scan_run_status": "Done"
    }));

    assert!(xml.contains(r#"<report id="report-1">"#));
    assert!(xml.contains("<scan_run_status>Done</scan_run_status>"));
}

#[test]
fn returns_error_when_top_level_json_is_not_object() {
    let err = build_audit_report_xml_from_json(&json!(["not", "an", "object"]))
        .expect_err("top-level array should fail");

    assert!(
        matches!(err, RenderError::BuildXml(message) if message == "audit report_json must be an object")
    );
}

#[test]
fn strips_null_fields_recursively() {
    let xml = build(json!({
        "report": {
            "present": "yes",
            "missing": null,
            "nested": {
                "kept": "value",
                "removed": null
            },
            "items": [
                {
                    "name": "first",
                    "null_field": null
                }
            ]
        }
    }));

    assert!(xml.contains("<present>yes</present>"));
    assert!(xml.contains("<nested><kept>value</kept></nested>"));
    assert!(xml.contains("<items><name>first</name></items>"));

    assert!(!xml.contains("missing"));
    assert!(!xml.contains("removed"));
    assert!(!xml.contains("null_field"));
}

#[test]
fn writes_empty_object_as_self_closing_node() {
    let xml = build(json!({
        "report": {
            "empty": {}
        }
    }));

    assert!(xml.contains("<empty/>"));
}

#[test]
fn writes_empty_array_as_no_repeated_child_nodes() {
    let xml = build(json!({
        "report": {
            "results": {
                "result": []
            },
            "after": "kept"
        }
    }));

    assert!(xml.contains("<results></results>") || xml.contains("<results/>"));
    assert!(xml.contains("<after>kept</after>"));
    assert!(!xml.contains("<result>"));
    assert!(!xml.contains("<result/>"));
}

#[test]
fn writes_array_items_as_repeated_nodes() {
    let xml = build(json!({
        "report": {
            "result": [
                {
                    "@id": "result-1",
                    "name": "First"
                },
                {
                    "@id": "result-2",
                    "name": "Second"
                }
            ]
        }
    }));

    assert!(xml.contains(r#"<result id="result-1"><name>First</name></result>"#));
    assert!(xml.contains(r#"<result id="result-2"><name>Second</name></result>"#));
}

#[test]
fn writes_attrs_from_attrs_object() {
    let xml = build(json!({
        "report": {
            "@attrs": {
                "id": "report-1",
                "extension": "xml"
            },
            "scan_run_status": "Done"
        }
    }));

    assert!(
        xml.contains(r#"<report extension="xml" id="report-1">"#)
            || xml.contains(r#"<report id="report-1" extension="xml">"#)
    );
    assert!(xml.contains("<scan_run_status>Done</scan_run_status>"));
}

#[test]
fn writes_attrs_from_at_prefixed_keys() {
    let xml = build(json!({
        "report": {
            "@id": "report-1",
            "@extension": "xml",
            "scan_run_status": "Done"
        }
    }));

    assert!(xml.contains(r#"id="report-1""#));
    assert!(xml.contains(r#"extension="xml""#));
    assert!(xml.contains("<scan_run_status>Done</scan_run_status>"));
    assert!(!xml.contains("<@id>"));
    assert!(!xml.contains("<@extension>"));
}

#[test]
fn ignores_null_attributes() {
    let xml = build(json!({
        "report": {
            "@id": null,
            "@attrs": {
                "extension": null,
                "content_type": "application/xml"
            },
            "name": "Report"
        }
    }));

    assert!(xml.contains(r#"content_type="application/xml""#));
    assert!(!xml.contains(r#"id=""#));
    assert!(!xml.contains(r#"extension=""#));
}

#[test]
fn writes_text_from_hash_text_key() {
    let xml = build(json!({
        "report": {
            "host": {
                "@asset_id": "asset-1",
                "#text": "192.0.2.10"
            }
        }
    }));

    assert!(xml.contains(r#"<host asset_id="asset-1">192.0.2.10</host>"#));
}

#[test]
fn writes_text_from_dollar_text_key() {
    let xml = build(json!({
        "report": {
            "host": {
                "@asset_id": "asset-1",
                "$text": "192.0.2.10"
            }
        }
    }));

    assert!(xml.contains(r#"<host asset_id="asset-1">192.0.2.10</host>"#));
}

#[test]
fn writes_text_before_child_nodes() {
    let xml = build(json!({
        "report": {
            "description": {
                "#text": "prefix ",
                "part": "child"
            }
        }
    }));

    assert!(xml.contains("<description>prefix <part>child</part></description>"));
}

#[test]
fn writes_string_number_and_bool_nodes() {
    let xml = build(json!({
        "report": {
            "name": "Audit Report",
            "count": 42,
            "enabled": true,
            "disabled": false
        }
    }));

    assert!(xml.contains("<name>Audit Report</name>"));
    assert!(xml.contains("<count>42</count>"));
    assert!(xml.contains("<enabled>true</enabled>"));
    assert!(xml.contains("<disabled>false</disabled>"));
}

#[test]
fn escapes_text_values() {
    let xml = build(json!({
        "report": {
            "description": "a < b && c > d"
        }
    }));

    assert!(xml.contains("<description>a &lt; b &amp;&amp; c &gt; d</description>"));
}

#[test]
fn escapes_attribute_values() {
    let xml = build(json!({
        "report": {
            "@name": "A \"quoted\" & <tag>",
            "status": "Done"
        }
    }));

    assert!(xml.contains(r#"name="A &quot;quoted&quot; &amp; &lt;tag&gt;""#));
}

#[test]
fn serializes_object_text_value_as_json_string_when_used_as_text() {
    let xml = build(json!({
        "report": {
            "field": {
                "#text": {
                    "nested": true
                }
            }
        }
    }));

    assert!(
        xml.contains("<field>{&quot;nested&quot;:true}</field>")
            || xml.contains("<field>{\"nested\":true}</field>")
    );
}

#[test]
fn serializes_array_text_value_as_json_string_when_used_as_text() {
    let xml = build(json!({
        "report": {
            "field": {
                "#text": [1, 2, 3]
            }
        }
    }));

    assert!(xml.contains("<field>[1,2,3]</field>"));
}

#[test]
fn strips_nulls_before_extracting_inner_report() {
    let xml = build(json!({
        "report": {
            "@id": "report-1",
            "null_field": null,
            "nested": {
                "value": "kept",
                "removed": null
            }
        },
        "outer_null": null
    }));

    assert!(xml.contains(r#"<report id="report-1">"#));
    assert!(xml.contains("<nested><value>kept</value></nested>"));

    assert!(!xml.contains("null_field"));
    assert!(!xml.contains("removed"));
    assert!(!xml.contains("outer_null"));
}
