use super::*;
use serde_json::json;

#[test]
fn returns_error_for_non_object_input() {
    let input = json!(["not", "object"]);

    let err = build_report_xml(&input).unwrap_err();

    assert!(matches!(err, ReportXmlBuildError::RootMustBeObject));
}

#[test]
fn strips_null_fields() {
    let input = json!({
        "report": {
            "name": null,
            "timestamp": "2026-04-24T00:00:00Z"
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(!xml.contains("<name>"));
    assert!(xml.contains("<timestamp>2026-04-24T00:00:00Z</timestamp>"));
}

#[test]
fn defaults_results_start_attribute() {
    let input = json!({
        "report": {
            "results": {
                "result": []
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#"<results start="1">"#));
}

#[test]
fn defaults_missing_result_host_to_empty_string() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "nvt": {
                        "@oid": "1.2.3"
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<host></host>"));
}

#[test]
fn defaults_null_result_host_to_empty_string() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": null,
                    "nvt": {
                        "@oid": "1.2.3"
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<host></host>"));
}

#[test]
fn adds_text_to_object_result_host() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": {
                        "hostname": "localhost"
                    },
                    "nvt": {
                        "@oid": "1.2.3"
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<host><hostname>localhost</hostname></host>"));
}

#[test]
fn converts_single_result_object_to_repeated_result_node() {
    let input = json!({
        "report": {
            "results": {
                "result": {
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "1.2.3"
                    }
                }
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<result>"));
    assert!(xml.contains("<host>127.0.0.1</host>"));
}

#[test]
fn defaults_missing_result_port_and_threat() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1"
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<port>general/tcp</port>"));
    assert!(xml.contains("<threat>Low</threat>"));
}

#[test]
fn normalizes_info_threat_to_low() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "threat": "Info"
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<threat>Low</threat>"));
}

#[test]
fn normalizes_scalar_ref_item_to_ref_id_attribute() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "1.2.3",
                        "refs": {
                            "ref": "CVE-2024-1234"
                        }
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#"<ref id="CVE-2024-1234"></ref>"#));
}

#[test]
fn normalizes_ref_type_and_id_to_attributes() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "1.2.3",
                        "refs": {
                            "ref": [{
                                "type": "cve",
                                "id": "CVE-2024-1234"
                            }]
                        }
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<ref "));
    assert!(xml.contains(r#"type="cve""#));
    assert!(xml.contains(r#"id="CVE-2024-1234""#));
}

#[test]
fn keeps_complex_ref_type_and_id_as_child_nodes() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "1.2.3",
                        "refs": {
                            "ref": [{
                                "type": { "name": "complex" },
                                "id": ["CVE-2024-1234"]
                            }]
                        }
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<type><name>complex</name></type>"));
    assert!(xml.contains("<id>CVE-2024-1234</id>"));
}

#[test]
fn keeps_existing_ref_attributes() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "1.2.3",
                        "refs": {
                            "ref": [{
                                "@type": "cve",
                                "@id": "CVE-2024-1234",
                                "type": "ignored",
                                "id": "ignored"
                            }]
                        }
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<ref "));
    assert!(xml.contains(r#"type="cve""#));
    assert!(xml.contains(r#"id="CVE-2024-1234""#));
    assert!(xml.contains("<type>ignored</type>"));
    assert!(xml.contains("<id>ignored</id>"));
}

#[test]
fn force_text_tag_uses_text_from_array_items() {
    let input = json!({
        "report": {
            "description": [
                { "#text": "line one" },
                { "#text": "line two" }
            ]
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<description>line one\nline two</description>"));
}

#[test]
fn force_text_tag_serializes_object_without_text_as_json() {
    let input = json!({
        "report": {
            "description": {
                "nested": "value"
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#""nested""#));
    assert!(xml.contains(r#""value""#));
}

#[test]
fn defaults_ports_start_attribute() {
    let input = json!({
        "report": {
            "ports": {
                "port": []
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#"<ports start="1">"#));
}

#[test]
fn maps_filter_phrase_to_term() {
    let input = json!({
        "report": {
            "filters": {
                "phrase": "severity > 0"
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains("<term>severity &gt; 0</term>"));
}

#[test]
fn writes_inline_and_nested_attributes() {
    let input = json!({
        "report": {
            "foo": {
                "@id": "abc",
                "@attrs": {
                    "name": "hello"
                },
                "#text": "value"
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#"<foo id="abc" name="hello">value</foo>"#));
}

#[test]
fn writes_nvt_oid_as_attribute_and_skips_oid_child() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "oid": "1.2.3",
                        "name": "Test NVT"
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#"<nvt oid="1.2.3">"#));
    assert!(!xml.contains("<oid>1.2.3</oid>"));
}

#[test]
fn normalizes_nvt_xref_to_ref_id_attribute() {
    let input = json!({
        "report": {
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "1.2.3",
                        "refs": {
                            "xref": ["CVE-2024-1234"]
                        }
                    }
                }]
            }
        }
    });

    let xml = build_report_xml(&input).unwrap();

    assert!(xml.contains(r#"<ref id="CVE-2024-1234"></ref>"#));
    assert!(!xml.contains("<xref>"));
}

#[test]
fn orders_host_ip_before_detail() {
    let input = json!({
        "report": {
            "host": [{
                "detail": [{
                    "name": "hostname",
                    "value": "localhost"
                }],
                "ip": "127.0.0.1"
            }]
        }
    });

    let xml = build_report_xml(&input).unwrap();

    let ip_pos = xml.find("<ip>127.0.0.1</ip>").unwrap();
    let detail_pos = xml.find("<detail>").unwrap();

    assert!(ip_pos < detail_pos);
}
