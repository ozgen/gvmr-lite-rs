// render_audit_tests.rs

use super::*;
use serde_json::json;

fn minimal_report_json() -> AuditReportEnvelopeJson {
    serde_json::from_value(json!({
        "report": {}
    }))
    .expect("minimal audit report json should deserialize")
}

fn render_request_with_timeout(timeout_seconds: u64) -> RenderAuditRequest {
    RenderAuditRequest {
        format_id: "compliance-pdf".to_string(),
        report_json: minimal_report_json(),
        params: Map::new(),
        output_name: None,
        timeout_seconds,
    }
}

fn render_xml_request_with_timeout(timeout_seconds: u64) -> RenderAuditXmlRequest {
    RenderAuditXmlRequest {
        format_id: "compliance-pdf".to_string(),
        report_xml: "<report/>".to_string(),
        params: Map::new(),
        output_name: None,
        timeout_seconds,
    }
}

#[test]
fn render_audit_request_validate_accepts_valid_request() {
    let request = render_request_with_timeout(300);

    assert_eq!(request.validate(), Ok(()));
}

#[test]
fn render_audit_request_validate_rejects_empty_format_id() {
    let mut request = render_request_with_timeout(300);
    request.format_id = "   ".to_string();

    assert_eq!(
        request.validate(),
        Err("format_id must not be empty".to_string())
    );
}

#[test]
fn render_audit_request_validate_accepts_timeout_boundaries() {
    assert_eq!(render_request_with_timeout(1).validate(), Ok(()));
    assert_eq!(render_request_with_timeout(40001).validate(), Ok(()));
}

#[test]
fn render_audit_request_validate_rejects_timeout_below_minimum() {
    let request = render_request_with_timeout(0);

    assert_eq!(
        request.validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn render_audit_request_validate_rejects_timeout_above_maximum() {
    let request = render_request_with_timeout(40002);

    assert_eq!(
        request.validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn render_audit_request_deserializes_default_params_and_timeout() {
    let request: RenderAuditRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_json": {
            "report": {}
        },
        "output_name": null
    }))
    .expect("request should deserialize");

    assert!(request.params.is_empty());
    assert_eq!(request.timeout_seconds, 300);
}

#[test]
fn render_audit_request_preserves_custom_params() {
    let request: RenderAuditRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_json": {
            "report": {}
        },
        "params": {
            "language": "en",
            "compact": true
        },
        "output_name": "audit-report.pdf",
        "timeout_seconds": 60
    }))
    .expect("request should deserialize");

    assert_eq!(request.params.get("language"), Some(&json!("en")));
    assert_eq!(request.params.get("compact"), Some(&json!(true)));
    assert_eq!(request.output_name.as_deref(), Some("audit-report.pdf"));
    assert_eq!(request.timeout_seconds, 60);
}

#[test]
fn render_audit_request_report_json_value_returns_envelope() {
    let request: RenderAuditRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_json": {
            "@attrs": {
                "id": "report-1"
            },
            "name": "Audit Report",
            "report": {
                "scan_run_status": "Done"
            },
            "custom_envelope_field": "kept"
        },
        "output_name": null
    }))
    .expect("request should deserialize");

    let value = request.report_json_value();

    assert_eq!(value["@attrs"]["id"], json!("report-1"));
    assert_eq!(value["name"], json!("Audit Report"));
    assert_eq!(value["report"]["scan_run_status"], json!("Done"));
    assert_eq!(value["custom_envelope_field"], json!("kept"));
}

#[test]
fn render_audit_request_inner_report_json_value_returns_only_report_body() {
    let request: RenderAuditRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_json": {
            "name": "Audit Report",
            "report": {
                "scan_run_status": "Done",
                "timestamp": "2026-06-04T10:00:00Z"
            }
        },
        "output_name": null
    }))
    .expect("request should deserialize");

    let value = request.inner_report_json_value();

    assert_eq!(value["scan_run_status"], json!("Done"));
    assert_eq!(value["timestamp"], json!("2026-06-04T10:00:00Z"));
    assert!(value.get("name").is_none());
    assert!(value.get("report").is_none());
}

#[test]
fn render_audit_xml_request_validate_accepts_valid_request() {
    let request = render_xml_request_with_timeout(300);

    assert_eq!(request.validate(), Ok(()));
}

#[test]
fn render_audit_xml_request_validate_rejects_empty_format_id() {
    let mut request = render_xml_request_with_timeout(300);
    request.format_id = "\n\t ".to_string();

    assert_eq!(
        request.validate(),
        Err("format_id must not be empty".to_string())
    );
}

#[test]
fn render_audit_xml_request_validate_rejects_empty_report_xml() {
    let mut request = render_xml_request_with_timeout(300);
    request.report_xml = "   ".to_string();

    assert_eq!(
        request.validate(),
        Err("report_xml must not be empty".to_string())
    );
}

#[test]
fn render_audit_xml_request_validate_accepts_timeout_boundaries() {
    assert_eq!(render_xml_request_with_timeout(1).validate(), Ok(()));
    assert_eq!(render_xml_request_with_timeout(40001).validate(), Ok(()));
}

#[test]
fn render_audit_xml_request_validate_rejects_invalid_timeout() {
    assert_eq!(
        render_xml_request_with_timeout(0).validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );

    assert_eq!(
        render_xml_request_with_timeout(40002).validate(),
        Err("timeout_seconds must be between 1 and 40001".to_string())
    );
}

#[test]
fn render_audit_xml_request_deserializes_default_params_and_timeout() {
    let request: RenderAuditXmlRequest = serde_json::from_value(json!({
        "format_id": "compliance-pdf",
        "report_xml": "<report/>",
        "output_name": null
    }))
    .expect("request should deserialize");

    assert!(request.params.is_empty());
    assert_eq!(request.timeout_seconds, 300);
}

#[test]
fn audit_report_body_defaults_collections_to_empty_vectors() {
    let body: AuditReportBodyJson =
        serde_json::from_value(json!({})).expect("empty report body should deserialize");

    assert!(body.host.is_empty());
    assert!(body.extra.is_empty());
}

#[test]
fn audit_report_envelope_preserves_unknown_fields() {
    let envelope: AuditReportEnvelopeJson = serde_json::from_value(json!({
        "@attrs": {
            "id": "audit-report-id"
        },
        "name": "Compliance Audit",
        "report": {},
        "unknown_field": {
            "nested": true
        }
    }))
    .expect("envelope should deserialize");

    assert_eq!(
        envelope.attrs.as_ref().and_then(|attrs| attrs.get("id")),
        Some(&json!("audit-report-id"))
    );
    assert_eq!(envelope.name.as_deref(), Some("Compliance Audit"));
    assert_eq!(
        envelope.extra.get("unknown_field"),
        Some(&json!({ "nested": true }))
    );
}

#[test]
fn audit_filter_keyword_defaults_relation_to_equals() {
    let keyword: AuditFilterKeywordJson = serde_json::from_value(json!({
        "column": "compliance",
        "value": "NO"
    }))
    .expect("keyword should deserialize");

    assert_eq!(keyword.column, "compliance");
    assert_eq!(keyword.relation, "=");
    assert_eq!(keyword.value, json!("NO"));
}

#[test]
fn audit_filters_deserializes_keywords_and_filter_terms() {
    let filters: AuditFiltersJson = serde_json::from_value(json!({
        "term": "compliance=NO",
        "phrase": "non compliant checks",
        "filter": ["first", "second"],
        "keywords": {
            "keyword": [
                {
                    "column": "compliance",
                    "relation": "=",
                    "value": "NO"
                }
            ]
        }
    }))
    .expect("filters should deserialize");

    assert_eq!(filters.term.as_deref(), Some("compliance=NO"));
    assert_eq!(filters.phrase.as_deref(), Some("non compliant checks"));
    assert_eq!(
        filters.filter,
        vec!["first".to_string(), "second".to_string()]
    );

    let keywords = filters.keywords.expect("keywords should exist");
    assert_eq!(keywords.keyword.len(), 1);
    assert_eq!(keywords.keyword[0].column, "compliance");
    assert_eq!(keywords.keyword[0].relation, "=");
    assert_eq!(keywords.keyword[0].value, json!("NO"));
}

#[test]
fn audit_result_host_deserializes_plain_string() {
    let result: AuditResultJson = serde_json::from_value(json!({
        "id": "result-1",
        "host": "192.0.2.10",
        "compliance": "NO"
    }))
    .expect("result should deserialize");

    match result.host {
        Some(AuditResultHostValueJson::String(host)) => {
            assert_eq!(host, "192.0.2.10");
        }
        other => panic!("expected string host, got {other:?}"),
    }

    assert_eq!(result.compliance.as_deref(), Some("NO"));
}

#[test]
fn audit_result_host_deserializes_object() {
    let result: AuditResultJson = serde_json::from_value(json!({
        "id": "result-1",
        "host": {
            "#text": "192.0.2.10",
            "hostname": "example-host",
            "asset": {
                "@attrs": {
                    "asset_id": "asset-1"
                }
            }
        },
        "compliance": "YES"
    }))
    .expect("result should deserialize");

    match result.host {
        Some(AuditResultHostValueJson::Object(host)) => {
            assert_eq!(host.text.as_deref(), Some("192.0.2.10"));
            assert_eq!(host.hostname.as_deref(), Some("example-host"));

            let asset = host.asset.expect("asset should exist");
            assert_eq!(
                asset.attrs.as_ref().and_then(|attrs| attrs.get("asset_id")),
                Some(&json!("asset-1"))
            );
        }
        other => panic!("expected object host, got {other:?}"),
    }

    assert_eq!(result.compliance.as_deref(), Some("YES"));
}

#[test]
fn audit_report_body_deserializes_compliance_counts() {
    let body: AuditReportBodyJson = serde_json::from_value(json!({
        "compliance_count": {
            "full": 152,
            "filtered": 152,
            "yes": {
                "full": 5,
                "filtered": 5
            },
            "no": {
                "full": 2,
                "filtered": 2
            },
            "incomplete": {
                "full": 145,
                "filtered": 145
            },
            "undefined": {
                "full": 0,
                "filtered": 0
            }
        }
    }))
    .expect("report body should deserialize");

    let count = body
        .compliance_count
        .expect("compliance count should exist");

    assert_eq!(count.full, Some(json!(152)));
    assert_eq!(count.filtered, Some(json!(152)));
    assert_eq!(count.yes.unwrap().full, Some(json!(5)));
    assert_eq!(count.no.unwrap().full, Some(json!(2)));
    assert_eq!(count.incomplete.unwrap().full, Some(json!(145)));
    assert_eq!(count.undefined.unwrap().full, Some(json!(0)));
}

#[test]
fn audit_report_body_deserializes_hosts_with_compliance_details() {
    let body: AuditReportBodyJson = serde_json::from_value(json!({
        "host": [
            {
                "ip": "192.0.2.10",
                "host_compliance": "NO",
                "compliance_count": {
                    "page": 152,
                    "yes": {
                        "page": 5
                    },
                    "no": {
                        "page": 2
                    },
                    "incomplete": {
                        "page": 145
                    },
                    "undefined": {
                        "page": 0
                    }
                },
                "detail": [
                    {
                        "name": "hostname",
                        "value": "test-host",
                        "source": {
                            "type": "gmp",
                            "name": "scanner",
                            "description": "source description"
                        },
                        "extra": "kept"
                    }
                ]
            }
        ]
    }))
    .expect("report body should deserialize");

    assert_eq!(body.host.len(), 1);

    let host = &body.host[0];
    assert_eq!(host.ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(host.host_compliance.as_deref(), Some("NO"));

    let count = host
        .compliance_count
        .as_ref()
        .expect("host compliance count should exist");

    assert_eq!(count.page, Some(json!(152)));
    assert_eq!(count.yes.as_ref().unwrap().page, Some(json!(5)));
    assert_eq!(count.no.as_ref().unwrap().page, Some(json!(2)));
    assert_eq!(count.incomplete.as_ref().unwrap().page, Some(json!(145)));
    assert_eq!(count.undefined.as_ref().unwrap().page, Some(json!(0)));

    assert_eq!(host.detail.len(), 1);

    let detail = &host.detail[0];
    assert_eq!(detail.name.as_deref(), Some("hostname"));
    assert_eq!(detail.value.as_deref(), Some("test-host"));
    assert_eq!(detail.extra.as_deref(), Some("kept"));

    let source = detail.source.as_ref().expect("detail source should exist");
    assert_eq!(source.kind.as_deref(), Some("gmp"));
    assert_eq!(source.name.as_deref(), Some("scanner"));
    assert_eq!(source.description.as_deref(), Some("source description"));
}

#[test]
fn audit_report_body_deserializes_results_with_compliance_values() {
    let body: AuditReportBodyJson = serde_json::from_value(json!({
        "results": {
            "result": [
                {
                    "id": "result-yes",
                    "name": "Compliant check",
                    "compliance": "YES",
                    "severity": 0
                },
                {
                    "id": "result-no",
                    "name": "Non-compliant check",
                    "compliance": "NO",
                    "severity": 10
                },
                {
                    "id": "result-incomplete",
                    "name": "Incomplete check",
                    "compliance": "INCOMPLETE",
                    "severity": 0
                }
            ]
        }
    }))
    .expect("report body should deserialize");

    let results = body.results.expect("results should exist");

    assert_eq!(results.result.len(), 3);
    assert_eq!(results.result[0].compliance.as_deref(), Some("YES"));
    assert_eq!(results.result[1].compliance.as_deref(), Some("NO"));
    assert_eq!(results.result[2].compliance.as_deref(), Some("INCOMPLETE"));
}

#[test]
fn audit_tls_certificates_deserialize_certificate_ports_and_host() {
    let certificates: AuditTlsCertificatesJson = serde_json::from_value(json!({
        "tls_certificate": [
            {
                "name": "cert-1",
                "sha256_fingerprint": "sha256-value",
                "md5_fingerprint": "md5-value",
                "valid": true,
                "activation_time": "2026-01-01T00:00:00Z",
                "expiration_time": "2027-01-01T00:00:00Z",
                "subject_dn": "CN=example",
                "issuer_dn": "CN=issuer",
                "serial": "123",
                "certificate": {
                    "@attrs": {
                        "id": "certificate-1"
                    },
                    "format": "PEM",
                    "#text": "-----BEGIN CERTIFICATE-----"
                },
                "host": {
                    "ip": "192.0.2.10",
                    "hostname": "example-host"
                },
                "ports": {
                    "port": ["443/tcp", "8443/tcp"]
                }
            }
        ]
    }))
    .expect("certificates should deserialize");

    assert_eq!(certificates.tls_certificate.len(), 1);

    let certificate = &certificates.tls_certificate[0];
    assert_eq!(certificate.name.as_deref(), Some("cert-1"));
    assert_eq!(
        certificate.sha256_fingerprint.as_deref(),
        Some("sha256-value")
    );
    assert_eq!(certificate.valid, Some(json!(true)));

    let certificate_body = certificate
        .certificate
        .as_ref()
        .expect("certificate body should exist");

    assert_eq!(
        certificate_body
            .attrs
            .as_ref()
            .and_then(|attrs| attrs.get("id")),
        Some(&json!("certificate-1"))
    );
    assert_eq!(certificate_body.format.as_deref(), Some("PEM"));
    assert_eq!(
        certificate_body.text.as_deref(),
        Some("-----BEGIN CERTIFICATE-----")
    );

    let host = certificate
        .host
        .as_ref()
        .expect("certificate host should exist");
    assert_eq!(host.ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(host.hostname.as_deref(), Some("example-host"));

    let ports = certificate
        .ports
        .as_ref()
        .expect("certificate ports should exist");
    assert_eq!(
        ports.port,
        vec!["443/tcp".to_string(), "8443/tcp".to_string()]
    );
}

#[test]
fn audit_errors_default_error_list_to_empty_vector() {
    let errors: AuditErrorsJson = serde_json::from_value(json!({
        "count": 0
    }))
    .expect("errors should deserialize");

    assert_eq!(errors.count, Some(json!(0)));
    assert!(errors.error.is_empty());
}

#[test]
fn audit_report_format_preserves_attrs_and_extra_fields() {
    let format: AuditReportFormatJson = serde_json::from_value(json!({
        "@attrs": {
            "id": "format-1"
        },
        "id": "format-id",
        "name": "PDF",
        "extension": "pdf",
        "content_type": "application/pdf",
        "custom": "kept"
    }))
    .expect("report format should deserialize");

    assert_eq!(
        format.attrs.as_ref().and_then(|attrs| attrs.get("id")),
        Some(&json!("format-1"))
    );
    assert_eq!(format.id.as_deref(), Some("format-id"));
    assert_eq!(format.name.as_deref(), Some("PDF"));
    assert_eq!(format.extension.as_deref(), Some("pdf"));
    assert_eq!(format.content_type.as_deref(), Some("application/pdf"));
    assert_eq!(format.extra.get("custom"), Some(&json!("kept")));
}

#[test]
fn audit_report_body_roundtrips_unknown_fields() {
    let body: AuditReportBodyJson = serde_json::from_value(json!({
        "scan_run_status": "Done",
        "custom_body_field": {
            "value": 42
        }
    }))
    .expect("report body should deserialize");

    let value = serde_json::to_value(body).expect("report body should serialize");

    assert_eq!(value["scan_run_status"], json!("Done"));
    assert_eq!(value["custom_body_field"], json!({ "value": 42 }));
}
