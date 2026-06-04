use super::*;

use serde_json::json;

#[test]
fn audit_result_host_address_returns_trimmed_text() {
    let host = AuditResultHost {
        text: Some(" 192.0.2.10 ".to_string()),
        ..Default::default()
    };

    assert_eq!(host.address(), Some("192.0.2.10"));
}

#[test]
fn audit_result_host_address_returns_none_for_empty_text() {
    let host = AuditResultHost {
        text: Some("   ".to_string()),
        ..Default::default()
    };

    assert_eq!(host.address(), None);
}

#[test]
fn audit_result_host_hostname_returns_trimmed_hostname() {
    let host = AuditResultHost {
        hostname: Some(" test-host ".to_string()),
        ..Default::default()
    };

    assert_eq!(host.hostname(), Some("test-host"));
}

#[test]
fn audit_result_host_hostname_returns_none_for_empty_hostname() {
    let host = AuditResultHost {
        hostname: Some("   ".to_string()),
        ..Default::default()
    };

    assert_eq!(host.hostname(), None);
}

#[test]
fn audit_result_host_display_name_prefers_hostname_over_address() {
    let host = AuditResultHost {
        text: Some("192.0.2.10".to_string()),
        hostname: Some("test-host".to_string()),
        ..Default::default()
    };

    assert_eq!(host.display_name(), Some("test-host"));
}

#[test]
fn audit_result_host_display_name_uses_last_hostname_segment() {
    let host = AuditResultHost {
        text: Some("192.0.2.10".to_string()),
        hostname: Some("example.com/test-host".to_string()),
        ..Default::default()
    };

    assert_eq!(host.display_name(), Some("test-host"));
}

#[test]
fn audit_result_host_display_name_falls_back_to_address() {
    let host = AuditResultHost {
        text: Some("192.0.2.10".to_string()),
        hostname: None,
        ..Default::default()
    };

    assert_eq!(host.display_name(), Some("192.0.2.10"));
}

#[test]
fn audit_result_host_display_name_ignores_empty_last_hostname_segment() {
    let host = AuditResultHost {
        text: Some("192.0.2.10".to_string()),
        hostname: Some("example.com/   ".to_string()),
        ..Default::default()
    };

    assert_eq!(host.display_name(), Some("192.0.2.10"));
}

#[test]
fn audit_report_envelope_deserializes_attribute_fields() {
    let envelope: AuditReportEnvelope = serde_json::from_value(json!({
        "@content_type": "application/xml",
        "@extension": "xml",
        "@id": "envelope-1",
        "@format_id": "format-1",
        "@config_id": "config-1",
        "name": "Audit Report",
        "report": {}
    }))
    .expect("envelope should deserialize");

    assert_eq!(envelope.content_type.as_deref(), Some("application/xml"));
    assert_eq!(envelope.extension.as_deref(), Some("xml"));
    assert_eq!(envelope.id.as_deref(), Some("envelope-1"));
    assert_eq!(envelope.format_id.as_deref(), Some("format-1"));
    assert_eq!(envelope.config_id.as_deref(), Some("config-1"));
    assert_eq!(envelope.name.as_deref(), Some("Audit Report"));
}

#[test]
fn audit_report_defaults_host_vector_to_empty() {
    let envelope: AuditReportEnvelope = serde_json::from_value(json!({
        "report": {}
    }))
    .expect("envelope should deserialize");

    assert!(envelope.report.host.is_empty());
}

#[test]
fn audit_filters_defaults_filter_vector_to_empty() {
    let filters: AuditFilters = serde_json::from_value(json!({
        "@id": "filter-1",
        "term": "compliance=NO"
    }))
    .expect("filters should deserialize");

    assert_eq!(filters.id.as_deref(), Some("filter-1"));
    assert_eq!(filters.term.as_deref(), Some("compliance=NO"));
    assert!(filters.filter.is_empty());
}

#[test]
fn audit_filter_keywords_defaults_keyword_vector_to_empty() {
    let keywords: AuditFilterKeywords =
        serde_json::from_value(json!({})).expect("keywords should deserialize");

    assert!(keywords.keyword.is_empty());
}

#[test]
fn audit_results_defaults_result_vector_to_empty() {
    let results: AuditResults = serde_json::from_value(json!({
        "@start": "1",
        "@max": "10"
    }))
    .expect("results should deserialize");

    assert_eq!(results.start.as_deref(), Some("1"));
    assert_eq!(results.max.as_deref(), Some("10"));
    assert!(results.result.is_empty());
}

#[test]
fn audit_ports_defaults_port_vector_to_empty() {
    let ports: AuditPorts = serde_json::from_value(json!({
        "@start": "1",
        "@max": "10",
        "count": "0"
    }))
    .expect("ports should deserialize");

    assert_eq!(ports.start.as_deref(), Some("1"));
    assert_eq!(ports.max.as_deref(), Some("10"));
    assert_eq!(ports.count.as_deref(), Some("0"));
    assert!(ports.port.is_empty());
}

#[test]
fn audit_result_deserializes_nested_host_asset_and_compliance() {
    let result: AuditResult = serde_json::from_value(json!({
        "@id": "result-1",
        "name": "Compliance check",
        "host": {
            "$text": "192.0.2.10",
            "hostname": "example.com/test-host",
            "asset": {
                "@asset_id": "asset-1"
            }
        },
        "port": "443/tcp",
        "severity": "10.0",
        "compliance": "NO"
    }))
    .expect("result should deserialize");

    assert_eq!(result.id.as_deref(), Some("result-1"));
    assert_eq!(result.name.as_deref(), Some("Compliance check"));
    assert_eq!(result.port.as_deref(), Some("443/tcp"));
    assert_eq!(result.severity.as_deref(), Some("10.0"));
    assert_eq!(result.compliance.as_deref(), Some("NO"));

    let host = result.host.expect("host should exist");

    assert_eq!(host.address(), Some("192.0.2.10"));
    assert_eq!(host.hostname(), Some("example.com/test-host"));
    assert_eq!(host.display_name(), Some("test-host"));

    let asset = host.asset.expect("asset should exist");

    assert_eq!(asset.asset_id.as_deref(), Some("asset-1"));
}

#[test]
fn audit_nvt_deserializes_type_oid_solution_and_refs() {
    let nvt: AuditNvt = serde_json::from_value(json!({
        "@oid": "1.3.6.1.4.1.example",
        "type": "nvt",
        "name": "Example NVT",
        "family": "General",
        "solution": {
            "@type": "VendorFix",
            "$text": "Install the vendor update."
        },
        "refs": {
            "ref": [
                {
                    "@type": "cve",
                    "@id": "CVE-2026-0001"
                }
            ]
        }
    }))
    .expect("nvt should deserialize");

    assert_eq!(nvt.oid.as_deref(), Some("1.3.6.1.4.1.example"));
    assert_eq!(nvt.kind.as_deref(), Some("nvt"));
    assert_eq!(nvt.name.as_deref(), Some("Example NVT"));
    assert_eq!(nvt.family.as_deref(), Some("General"));

    let solution = nvt.solution.expect("solution should exist");

    assert_eq!(solution.kind.as_deref(), Some("VendorFix"));
    assert_eq!(solution.text.as_deref(), Some("Install the vendor update."));

    let refs = nvt.refs.expect("refs should exist");

    assert_eq!(refs.reference.len(), 1);
    assert_eq!(refs.reference[0].kind.as_deref(), Some("cve"));
    assert_eq!(refs.reference[0].id.as_deref(), Some("CVE-2026-0001"));
}

#[test]
fn audit_compliance_count_deserializes_total_and_status_counts() {
    let count: AuditComplianceCount = serde_json::from_value(json!({
        "$text": "152",
        "full": "152",
        "filtered": "152",
        "yes": {
            "full": "5",
            "filtered": "5"
        },
        "no": {
            "full": "2",
            "filtered": "2"
        },
        "incomplete": {
            "full": "145",
            "filtered": "145"
        },
        "undefined": {
            "full": "0",
            "filtered": "0"
        }
    }))
    .expect("compliance count should deserialize");

    assert_eq!(count.total.as_deref(), Some("152"));
    assert_eq!(count.full.as_deref(), Some("152"));
    assert_eq!(count.filtered.as_deref(), Some("152"));

    assert_eq!(count.yes.unwrap().full.as_deref(), Some("5"));
    assert_eq!(count.no.unwrap().full.as_deref(), Some("2"));
    assert_eq!(count.incomplete.unwrap().full.as_deref(), Some("145"));
    assert_eq!(count.undefined.unwrap().full.as_deref(), Some("0"));
}

#[test]
fn audit_host_deserializes_compliance_counts_and_details() {
    let host: AuditHost = serde_json::from_value(json!({
        "ip": "192.0.2.10",
        "host_compliance": "NO",
        "asset": {
            "@asset_id": "asset-1"
        },
        "compliance_count": {
            "page": "152",
            "yes": {
                "page": "5"
            },
            "no": {
                "page": "2"
            },
            "incomplete": {
                "page": "145"
            },
            "undefined": {
                "page": "0"
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
    }))
    .expect("host should deserialize");

    assert_eq!(host.ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(host.host_compliance.as_deref(), Some("NO"));
    assert_eq!(host.asset.unwrap().asset_id.as_deref(), Some("asset-1"));

    let count = host
        .compliance_count
        .expect("compliance count should exist");

    assert_eq!(count.page.as_deref(), Some("152"));
    assert_eq!(count.yes.unwrap().page.as_deref(), Some("5"));
    assert_eq!(count.no.unwrap().page.as_deref(), Some("2"));
    assert_eq!(count.incomplete.unwrap().page.as_deref(), Some("145"));
    assert_eq!(count.undefined.unwrap().page.as_deref(), Some("0"));

    assert_eq!(host.detail.len(), 1);

    let detail = &host.detail[0];

    assert_eq!(detail.name.as_deref(), Some("hostname"));
    assert_eq!(detail.value.as_deref(), Some("test-host"));
    assert_eq!(detail.extra.as_deref(), Some("kept"));

    let source = detail.source.as_ref().expect("source should exist");

    assert_eq!(source.kind.as_deref(), Some("gmp"));
    assert_eq!(source.name.as_deref(), Some("scanner"));
    assert_eq!(source.description.as_deref(), Some("source description"));
}

#[test]
fn audit_report_serializes_attribute_and_text_fields() {
    let result = AuditResult {
        id: Some("result-1".to_string()),
        name: Some("Compliance check".to_string()),
        host: Some(AuditResultHost {
            text: Some("192.0.2.10".to_string()),
            hostname: Some("test-host".to_string()),
            asset: Some(AuditAsset {
                asset_id: Some("asset-1".to_string()),
            }),
        }),
        compliance: Some("YES".to_string()),
        ..Default::default()
    };

    let value = serde_json::to_value(result).expect("result should serialize");

    assert_eq!(value["@id"], json!("result-1"));
    assert_eq!(value["name"], json!("Compliance check"));
    assert_eq!(value["host"]["$text"], json!("192.0.2.10"));
    assert_eq!(value["host"]["hostname"], json!("test-host"));
    assert_eq!(value["host"]["asset"]["@asset_id"], json!("asset-1"));
    assert_eq!(value["compliance"], json!("YES"));
}
