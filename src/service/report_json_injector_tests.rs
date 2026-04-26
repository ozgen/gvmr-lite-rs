mod tests {
    use crate::service::report_json_injector::inject_graph_gen_fields;

    use serde_json::json;

    #[test]
    fn converts_single_result_object_to_array() {
        let input = json!({
            "results": {
                "result": {
                    "host": "127.0.0.1"
                }
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert!(output["results"]["result"].is_array());
        assert_eq!(output["results"]["result"][0]["host"], "127.0.0.1");
    }

    #[test]
    fn moves_nvt_oid_to_attribute_oid() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "oid": "1.2.3.4"
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        let nvt = &output["results"]["result"][0]["nvt"];

        assert_eq!(nvt["@oid"], "1.2.3.4");
        assert!(nvt.get("oid").is_none());
    }

    #[test]
    fn keeps_existing_attribute_oid() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "@oid": "existing",
                        "oid": "ignored"
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        let nvt = &output["results"]["result"][0]["nvt"];

        assert_eq!(nvt["@oid"], "existing");
        assert_eq!(nvt["oid"], "ignored");
    }

    #[test]
    fn extracts_cves_from_xrefs() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "refs": {
                            "xref": [
                                "CVE-2024-1234",
                                "https://example.test/CVE-2024-99999"
                            ]
                        }
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(
            output["results"]["result"][0]["nvt"]["cve"],
            "CVE-2024-1234, CVE-2024-99999"
        );
    }

    #[test]
    fn joins_existing_cve_array() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "cve": ["CVE-2024-1234", "", "CVE-2024-9999"]
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(
            output["results"]["result"][0]["nvt"]["cve"],
            "CVE-2024-1234, CVE-2024-9999"
        );
    }

    #[test]
    fn extracts_cves_from_ref_objects_with_id() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "refs": {
                            "ref": [
                                {
                                    "@type": "cve",
                                    "@id": "CVE-2024-1234"
                                },
                                {
                                    "@type": "url",
                                    "@id": "https://example.test/CVE-2024-99999"
                                }
                            ]
                        }
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(
            output["results"]["result"][0]["nvt"]["cve"],
            "CVE-2024-1234, CVE-2024-99999"
        );
    }

    #[test]
    fn extracts_cves_from_ref_scalar_values() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "refs": {
                            "ref": [
                                "CVE-2024-1234",
                                "https://example.test/CVE-2024-99999"
                            ]
                        }
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(
            output["results"]["result"][0]["nvt"]["cve"],
            "CVE-2024-1234, CVE-2024-99999"
        );
    }

    #[test]
    fn joins_existing_cve_array_with_different_json_value_types() {
        let input = json!({
            "results": {
                "result": [{
                    "host": "127.0.0.1",
                    "nvt": {
                        "cve": [
                            "CVE-2024-1234",
                            123,
                            true,
                            null,
                            { "id": "CVE-2024-9999" }
                        ]
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(
            output["results"]["result"][0]["nvt"]["cve"],
            "CVE-2024-1234, 123, true, {\"id\":\"CVE-2024-9999\"}"
        );
    }

    #[test]
    fn defaults_missing_result_host_to_empty_string() {
        let input = json!({
            "results": {
                "result": [{
                    "nvt": {
                        "@oid": "1.2.3"
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(output["results"]["result"][0]["host"], "");
    }

    #[test]
    fn adds_text_field_to_object_host() {
        let input = json!({
            "results": {
                "result": [{
                    "host": {
                        "hostname": "localhost"
                    }
                }]
            }
        });

        let output = inject_graph_gen_fields(&input).unwrap();

        assert_eq!(output["results"]["result"][0]["host"]["#text"], "");
        assert_eq!(
            output["results"]["result"][0]["host"]["hostname"],
            "localhost"
        );
    }

    #[test]
    fn returns_error_for_non_object_input() {
        let input = json!(["not", "an", "object"]);

        let err = inject_graph_gen_fields(&input).unwrap_err();

        assert_eq!(err, "Expected dict-like report_json");
    }
}
