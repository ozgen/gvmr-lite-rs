use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use super::*;
use crate::api::dto::render as dto;

fn report_json_from_value(value: Value) -> dto::ReportJson {
    serde_json::from_value(value).unwrap()
}

fn attrs(values: &[(&str, Value)]) -> Map<String, Value> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

fn dto_from_value<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

#[test]
fn report_json_to_envelope_maps_top_level_fields_and_inner_report_id() {
    let report_json = dto::ReportJson {
        attrs: Some(attrs(&[
            ("id", json!("report-id")),
            ("format_id", json!("format-id")),
            ("config_id", json!("config-id")),
        ])),
        scan_run_status: Some("Done".to_string()),
        ..Default::default()
    };

    let envelope = report_json_to_envelope(&report_json);

    assert_eq!(envelope.id.as_deref(), Some("report-id"));
    assert_eq!(envelope.format_id.as_deref(), Some("format-id"));
    assert_eq!(envelope.config_id.as_deref(), Some("config-id"));
    assert_eq!(envelope.name.as_deref(), Some("Scan Report"));

    assert_eq!(envelope.report.id.as_deref(), Some("report-id"));
    assert_eq!(envelope.report.scan_run_status.as_deref(), Some("Done"));
}

#[test]
fn report_json_to_envelope_maps_gmp_version() {
    let report_json = dto::ReportJson {
        gmp: Some(attrs(&[("version", json!("22.5"))])),
        ..Default::default()
    };

    let envelope = report_json_to_envelope(&report_json);

    assert_eq!(
        envelope.report.gmp.unwrap().version.as_deref(),
        Some("22.5")
    );
}

#[test]
fn report_json_to_envelope_maps_filters_and_keywords() {
    let mut report_json = dto::ReportJson::default();

    report_json.filters.attrs = Some(attrs(&[("id", json!("filter-id"))]));

    report_json.filters.term = "severity>5".to_string();
    report_json.filters.filter = vec!["High only".to_string()];

    report_json.filters.keywords.keyword = vec![
        dto::FilterKeyword {
            column: "severity".to_string(),
            relation: ">".to_string(),
            value: dto::Scalar::Integer(5),
            extra: Map::new(),
        },
        dto::FilterKeyword {
            column: "threat".to_string(),
            relation: "=".to_string(),
            value: dto::Scalar::String("High".to_string()),
            extra: Map::new(),
        },
        dto::FilterKeyword {
            column: "active".to_string(),
            relation: "=".to_string(),
            value: dto::Scalar::Bool(true),
            extra: Map::new(),
        },
    ];

    let envelope = report_json_to_envelope(&report_json);
    let filters = envelope.report.filters.unwrap();

    assert_eq!(filters.id.as_deref(), Some("filter-id"));
    assert_eq!(filters.term.as_deref(), Some("severity>5"));
    assert_eq!(filters.filter, vec!["High only".to_string()]);

    let keywords = filters.keywords.unwrap().keyword;

    assert_eq!(keywords.len(), 3);

    assert_eq!(keywords[0].column.as_deref(), Some("severity"));
    assert_eq!(keywords[0].relation.as_deref(), Some(">"));
    assert_eq!(keywords[0].value.as_deref(), Some("5"));

    assert_eq!(keywords[1].column.as_deref(), Some("threat"));
    assert_eq!(keywords[1].relation.as_deref(), Some("="));
    assert_eq!(keywords[1].value.as_deref(), Some("High"));

    assert_eq!(keywords[2].column.as_deref(), Some("active"));
    assert_eq!(keywords[2].relation.as_deref(), Some("="));
    assert_eq!(keywords[2].value.as_deref(), Some("true"));
}

#[test]
fn filters_from_dto_omits_blank_term() {
    let report_json = report_json_from_value(json!({
        "filters": {
            "term": "   ",
            "keywords": {
                "keyword": []
            }
        },
        "ports": {
            "port": []
        },
        "results": {
            "result": []
        },
        "result_count": {
            "filtered": 0
        },
        "host": []
    }));

    let envelope = report_json_to_envelope(&report_json);

    assert_eq!(envelope.report.filters.unwrap().term, None);
}

#[test]
fn report_json_to_envelope_maps_count_nodes() {
    let report_json = report_json_from_value(json!({
        "filters": {
            "term": "",
            "keywords": {
                "keyword": []
            }
        },
        "hosts": {
            "count": 2
        },
        "closed_cves": {
            "count": 3
        },
        "vulns": {
            "count": 4
        },
        "os": {
            "count": 5
        },
        "apps": {
            "count": 6
        },
        "ssl_certs": {
            "count": 7
        },
        "ports": {
            "port": []
        },
        "results": {
            "result": []
        },
        "result_count": {
            "filtered": 0
        },
        "host": []
    }));

    let envelope = report_json_to_envelope(&report_json);

    assert_eq!(envelope.report.hosts.unwrap().count.as_deref(), Some("2"));
    assert_eq!(
        envelope.report.closed_cves.unwrap().count.as_deref(),
        Some("3")
    );
    assert_eq!(envelope.report.vulns.unwrap().count.as_deref(), Some("4"));
    assert_eq!(envelope.report.os.unwrap().count.as_deref(), Some("5"));
    assert_eq!(envelope.report.apps.unwrap().count.as_deref(), Some("6"));
    assert_eq!(
        envelope.report.ssl_certs.unwrap().count.as_deref(),
        Some("7")
    );
}

#[test]
fn report_json_to_envelope_maps_task_and_target() {
    let report_json = report_json_from_value(json!({
        "filters": {
            "term": "",
            "keywords": {
                "keyword": []
            }
        },
        "task": {
            "id": "task-id",
            "name": "Task Name",
            "comment": "Task comment",
            "progress": 42,
            "target": {
                "id": "target-id",
                "trash": false,
                "name": "Target Name",
                "comment": "Target comment"
            }
        },
        "ports": {
            "port": []
        },
        "results": {
            "result": []
        },
        "result_count": {
            "filtered": 0
        },
        "host": []
    }));

    let envelope = report_json_to_envelope(&report_json);
    let task = envelope.report.task.unwrap();
    let target = task.target.unwrap();

    assert_eq!(task.id.as_deref(), Some("task-id"));
    assert_eq!(task.name.as_deref(), Some("Task Name"));
    assert_eq!(task.comment.as_deref(), Some("Task comment"));
    assert_eq!(task.progress.as_deref(), Some("42"));

    assert_eq!(target.id.as_deref(), Some("target-id"));
    assert_eq!(target.trash.as_deref(), Some("false"));
    assert_eq!(target.name.as_deref(), Some("Target Name"));
    assert_eq!(target.comment.as_deref(), Some("Target comment"));
}

#[test]
fn report_json_to_envelope_maps_timestamps_timezone_ports_and_severity() {
    let report_json = dto::ReportJson {
        timestamp: Some("2026-01-01T10:00:00Z".to_string()),
        scan_start: Some("2026-01-01T09:00:00Z".to_string()),
        scan_end: Some("2026-01-01T10:00:00Z".to_string()),
        timezone: Some("Europe/Berlin".to_string()),
        timezone_abbrev: Some("CET".to_string()),
        ports: dto::Ports {
            attrs: Some(attrs(&[("start", json!("1")), ("max", json!("10"))])),
            count: Some(2),
            ..Default::default()
        },
        severity: Some(dto::SeveritySummary {
            full: Some(json!(8.7)),
            filtered: Some(json!(7.1)),
            extra: Map::new(),
        }),
        ..Default::default()
    };

    let envelope = report_json_to_envelope(&report_json);

    assert_eq!(
        envelope.report.timestamp.as_deref(),
        Some("2026-01-01T10:00:00Z")
    );
    assert_eq!(
        envelope.report.scan_start.as_deref(),
        Some("2026-01-01T09:00:00Z")
    );
    assert_eq!(
        envelope.report.scan_end.as_deref(),
        Some("2026-01-01T10:00:00Z")
    );
    assert_eq!(envelope.report.timezone.as_deref(), Some("Europe/Berlin"));
    assert_eq!(envelope.report.timezone_abbrev.as_deref(), Some("CET"));

    let ports = envelope.report.ports.unwrap();

    assert_eq!(ports.start.as_deref(), Some("1"));
    assert_eq!(ports.max.as_deref(), Some("10"));
    assert_eq!(ports.count.as_deref(), Some("2"));

    let severity = envelope.report.severity.unwrap();

    assert_eq!(severity.full.as_deref(), Some("8.7"));
    assert_eq!(severity.filtered.as_deref(), Some("7.1"));
}

#[test]
fn results_from_dto_filters_info_log_debug_false_positive_and_empty_threats() {
    let report_json = report_json_from_value(json!({
        "filters": {
            "term": "",
            "keywords": {
                "keyword": []
            }
        },
        "ports": {
            "port": []
        },
        "results": {
            "attrs": {
                "start": "1",
                "max": "1000"
            },
            "result": [
                {
                    "host": "host-a",
                    "port": "443/tcp",
                    "threat": "High"
                },
                {
                    "host": "host-a",
                    "threat": "Info"
                },
                {
                    "host": "host-a",
                    "threat": "Log"
                },
                {
                    "host": "host-a",
                    "threat": "Debug"
                },
                {
                    "host": "host-a",
                    "threat": "False Positive"
                },
                {
                    "host": "host-a",
                    "threat": "   "
                }
            ]
        },
        "result_count": {
            "filtered": 0
        },
        "host": []
    }));

    let envelope = report_json_to_envelope(&report_json);
    let results = envelope.report.results.unwrap();

    assert_eq!(results.result.len(), 1);
    assert_eq!(results.result[0].threat.as_deref(), Some("High"));
    assert_eq!(results.result[0].port.as_deref(), Some("443/tcp"));

    let host = results.result[0].host.as_ref().unwrap();

    assert_eq!(host.text.as_deref(), Some("host-a"));
}

#[test]
fn result_count_from_dto_maps_all_count_buckets() {
    let report_json = report_json_from_value(json!({
        "filters": {
            "term": "",
            "keywords": {
                "keyword": []
            }
        },
        "ports": {
            "port": []
        },
        "results": {
            "result": []
        },
        "result_count": {
            "full": 10,
            "filtered": 5,
            "critical": {
                "full": 1,
                "filtered": 1
            },
            "hole": {
                "full": 2,
                "filtered": 1
            },
            "high": {
                "full": 3,
                "filtered": 2
            },
            "info": {
                "full": 4,
                "filtered": 0
            },
            "low": {
                "full": 5,
                "filtered": 3
            },
            "log": {
                "full": 6,
                "filtered": 4
            },
            "warning": {
                "full": 7,
                "filtered": 5
            },
            "medium": {
                "full": 8,
                "filtered": 6
            },
            "false_positive": {
                "full": 9,
                "filtered": 7
            }
        },
        "host": []
    }));

    let envelope = report_json_to_envelope(&report_json);
    let count = envelope.report.result_count.unwrap();

    assert_eq!(count.full.as_deref(), Some("10"));
    assert_eq!(count.filtered.as_deref(), Some("5"));

    assert_eq!(count.critical.unwrap().full.as_deref(), Some("1"));
    assert_eq!(count.hole.unwrap().filtered.as_deref(), Some("1"));
    assert_eq!(count.high.unwrap().full.as_deref(), Some("3"));
    assert_eq!(count.info.unwrap().full.as_deref(), Some("4"));
    assert_eq!(count.low.unwrap().filtered.as_deref(), Some("3"));
    assert_eq!(count.log.unwrap().filtered.as_deref(), Some("4"));
    assert_eq!(count.warning.unwrap().full.as_deref(), Some("7"));
    assert_eq!(count.medium.unwrap().filtered.as_deref(), Some("6"));
    assert_eq!(count.false_positive.unwrap().full.as_deref(), Some("9"));
}

#[test]
fn solution_from_map_supports_text_aliases_and_type_fallback() {
    let mut map = Map::new();
    map.insert("type".to_string(), json!("Mitigation"));
    map.insert("$text".to_string(), json!("Use a firewall"));

    let solution = solution_from_map(&map);

    assert_eq!(solution.r#type.as_deref(), Some("Mitigation"));
    assert_eq!(solution.text.as_deref(), Some("Use a firewall"));

    let mut map = Map::new();
    map.insert("text".to_string(), json!("Plain text"));

    let solution = solution_from_map(&map);

    assert_eq!(solution.r#type, None);
    assert_eq!(solution.text.as_deref(), Some("Plain text"));
}

#[test]
fn refs_from_map_supports_single_object_array_string_and_ignores_blank_ids() {
    let mut attrs = Map::new();
    attrs.insert("id".to_string(), json!("CVE-2026-0001"));
    attrs.insert("type".to_string(), json!("cve"));

    let mut object_ref = Map::new();
    object_ref.insert("@attrs".to_string(), Value::Object(attrs));

    let mut direct_ref = Map::new();
    direct_ref.insert("id".to_string(), json!("BID-123"));
    direct_ref.insert("type".to_string(), json!("bid"));

    let mut blank_ref = Map::new();
    blank_ref.insert("id".to_string(), json!("   "));

    let mut refs_map = Map::new();
    refs_map.insert(
        "ref".to_string(),
        json!([
            Value::Object(object_ref),
            Value::Object(direct_ref),
            "URL-1",
            Value::Object(blank_ref),
            "",
            null
        ]),
    );

    let refs = refs_from_map(&refs_map);

    assert_eq!(refs.reference.len(), 3);

    assert_eq!(refs.reference[0].id.as_deref(), Some("CVE-2026-0001"));
    assert_eq!(refs.reference[0].r#type.as_deref(), Some("cve"));

    assert_eq!(refs.reference[1].id.as_deref(), Some("BID-123"));
    assert_eq!(refs.reference[1].r#type.as_deref(), Some("bid"));

    assert_eq!(refs.reference[2].id.as_deref(), Some("URL-1"));
    assert_eq!(refs.reference[2].r#type, None);
}

#[test]
fn refs_from_map_supports_map_without_ref_key() {
    let mut map = Map::new();
    map.insert("id".to_string(), json!("CVE-2026-0002"));
    map.insert("type".to_string(), json!("cve"));

    let refs = refs_from_map(&map);

    assert_eq!(refs.reference.len(), 1);
    assert_eq!(refs.reference[0].id.as_deref(), Some("CVE-2026-0002"));
    assert_eq!(refs.reference[0].r#type.as_deref(), Some("cve"));
}

#[test]
fn qod_from_value_maps_object_and_scalar_values() {
    let qod = qod_from_value(&json!({
        "value": 95,
        "@type": "remote_banner"
    }));

    assert_eq!(qod.value.as_deref(), Some("95"));
    assert_eq!(qod.r#type.as_deref(), Some("remote_banner"));

    let qod = qod_from_value(&json!(80));

    assert_eq!(qod.value.as_deref(), Some("80"));
    assert_eq!(qod.r#type, None);
}

#[test]
fn attr_string_reads_direct_and_at_prefixed_keys() {
    let mut attrs = Map::new();
    attrs.insert("id".to_string(), json!("direct-id"));
    attrs.insert("@format_id".to_string(), json!("format-id"));

    assert_eq!(
        attr_string(Some(&attrs), "id").as_deref(),
        Some("direct-id")
    );
    assert_eq!(
        attr_string(Some(&attrs), "format_id").as_deref(),
        Some("format-id")
    );
    assert_eq!(attr_string(Some(&attrs), "missing"), None);
    assert_eq!(attr_string(None, "id"), None);
}

#[test]
fn value_to_string_from_value_maps_supported_json_values() {
    assert_eq!(value_to_string_from_value(&Value::Null), None);
    assert_eq!(
        value_to_string_from_value(&json!("text")).as_deref(),
        Some("text")
    );
    assert_eq!(
        value_to_string_from_value(&json!(42)).as_deref(),
        Some("42")
    );
    assert_eq!(
        value_to_string_from_value(&json!(true)).as_deref(),
        Some("true")
    );
    assert_eq!(
        value_to_string_from_value(&json!([1, 2])).as_deref(),
        Some("[1,2]")
    );
    assert_eq!(
        value_to_string_from_value(&json!({"a": 1})).as_deref(),
        Some("{\"a\":1}")
    );
}

#[test]
fn scalar_to_string_maps_all_scalar_variants() {
    assert_eq!(
        scalar_to_string(&dto::Scalar::String("text".to_string())),
        "text"
    );
    assert_eq!(scalar_to_string(&dto::Scalar::Integer(42)), "42");
    assert_eq!(scalar_to_string(&dto::Scalar::Float(4.2)), "4.2");
    assert_eq!(scalar_to_string(&dto::Scalar::Bool(true)), "true");
}

#[test]
fn should_keep_result_filters_expected_threats() {
    let high = report_json_from_value(json!({
        "filters": {
            "term": "",
            "keywords": {
                "keyword": []
            }
        },
        "ports": {
            "port": []
        },
        "results": {
            "result": [
                {
                    "host": "host-a",
                    "threat": "High"
                }
            ]
        },
        "result_count": {
            "filtered": 1
        },
        "host": []
    }));

    let high_result = &high.results.result[0];

    assert!(should_keep_result(high_result));

    for threat in ["", "   ", "Info", "Log", "Debug", "False Positive"] {
        let value = report_json_from_value(json!({
            "filters": {
                "term": "",
                "keywords": {
                    "keyword": []
                }
            },
            "ports": {
                "port": []
            },
            "results": {
                "result": [
                    {
                        "host": "host-a",
                        "threat": threat
                    }
                ]
            },
            "result_count": {
                "filtered": 1
            },
            "host": []
        }));

        assert!(!should_keep_result(&value.results.result[0]));
    }
}

#[test]
fn owner_from_dto_maps_owner_name() {
    let owner: dto::Owner = dto_from_value(json!({
        "name": "Owner Name"
    }));

    let result = owner_from_dto(&owner);

    assert_eq!(result.name.as_deref(), Some("Owner Name"));
}

#[test]
fn result_host_from_dto_maps_string_host() {
    let host: dto::HostValue = dto_from_value(json!("192.168.1.10"));

    let result = result_host_from_dto(&host);

    assert_eq!(result.text.as_deref(), Some("192.168.1.10"));
    assert!(result.asset.is_none());
    assert!(result.hostname.is_none());
}

#[test]
fn result_host_from_dto_maps_object_host_text_and_hostname() {
    let host = dto::HostValue::Object(dto::ResultHost {
        text: Some("192.168.1.10".to_string()),
        asset: None,
        hostname: Some("example.local".to_string()),
        extra: Map::new(),
    });

    let result = result_host_from_dto(&host);

    assert_eq!(result.text.as_deref(), Some("192.168.1.10"));
    assert_eq!(result.hostname.as_deref(), Some("example.local"));
    assert!(result.asset.is_none());
}

#[test]
fn asset_ref_from_dto_maps_asset_id_from_attrs() {
    let asset: dto::AssetRef = dto_from_value(json!({
        "@attrs": {
            "asset_id": "asset-id"
        }
    }));

    let result = asset_ref_from_dto(&asset);

    assert_eq!(result.asset_id.as_deref(), Some("asset-id"));
}

#[test]
fn nvt_from_dto_maps_core_fields() {
    let nvt: dto::Nvt = dto_from_value(json!({
        "attrs": {
            "oid": "1.2.3.4"
        },
        "type": "nvt",
        "name": "NVT Name",
        "family": "NVT Family",
        "cvss_base": 8.7,
        "tags": "summary=Summary text|impact=Impact text"
    }));

    let result = nvt_from_dto(&nvt);

    assert_eq!(result.r#type.as_deref(), Some("nvt"));
    assert_eq!(result.name.as_deref(), Some("NVT Name"));
    assert_eq!(result.family.as_deref(), Some("NVT Family"));
    assert_eq!(result.cvss_base.as_deref(), Some("8.7"));
    assert_eq!(
        result.tags.as_deref(),
        Some("summary=Summary text|impact=Impact text")
    );
}

#[test]
fn report_host_from_dto_maps_asset_counts_and_details() {
    let host: dto::HostEntry = dto_from_value(json!({
        "ip": "192.168.1.10",
        "asset": {
            "attrs": {
                "asset_id": "asset-id"
            },
            "@attrs": {
                "asset_id": "asset-id"
            }
        },
        "start": "2026-01-01T09:00:00Z",
        "end": "2026-01-01T10:00:00Z",
        "port_count": {
            "page": 2
        },
        "result_count": {
            "page": 3,
            "critical": {
                "page": 1
            },
            "hole": {
                "page": 2
            },
            "high": {
                "page": 3
            },
            "warning": {
                "page": 4
            },
            "medium": {
                "page": 5
            },
            "info": {
                "page": 6
            },
            "low": {
                "page": 7
            },
            "log": {
                "page": 8
            },
            "false_positive": {
                "page": 9
            }
        },
        "detail": [
            {
                "name": "OS",
                "value": "Linux",
                "source": {
                    "type": "nvt",
                    "name": "Source Name",
                    "description": "Source Description"
                },
                "extra": "extra-value"
            }
        ]
    }));

    let result = report_host_from_dto(&host);

    assert_eq!(result.ip.as_deref(), Some("192.168.1.10"));
    assert_eq!(
        result.asset.as_ref().unwrap().asset_id.as_deref(),
        Some("asset-id")
    );
    assert_eq!(result.start.as_deref(), Some("2026-01-01T09:00:00Z"));
    assert_eq!(result.end.as_deref(), Some("2026-01-01T10:00:00Z"));

    assert_eq!(
        result.port_count.as_ref().unwrap().page.as_deref(),
        Some("2")
    );

    let result_count = result.result_count.as_ref().unwrap();

    assert_eq!(result_count.page.as_deref(), Some("3"));
    assert_eq!(
        result_count.critical.as_ref().unwrap().page.as_deref(),
        Some("1")
    );
    assert_eq!(
        result_count.hole.as_ref().unwrap().page.as_deref(),
        Some("2")
    );
    assert_eq!(
        result_count.high.as_ref().unwrap().page.as_deref(),
        Some("3")
    );
    assert_eq!(
        result_count.warning.as_ref().unwrap().page.as_deref(),
        Some("4")
    );
    assert_eq!(
        result_count.medium.as_ref().unwrap().page.as_deref(),
        Some("5")
    );
    assert_eq!(
        result_count.info.as_ref().unwrap().page.as_deref(),
        Some("6")
    );
    assert_eq!(
        result_count.low.as_ref().unwrap().page.as_deref(),
        Some("7")
    );
    assert_eq!(
        result_count.log.as_ref().unwrap().page.as_deref(),
        Some("8")
    );
    assert_eq!(
        result_count
            .false_positive
            .as_ref()
            .unwrap()
            .page
            .as_deref(),
        Some("9")
    );

    let detail = &result.detail[0];

    assert_eq!(detail.name.as_deref(), Some("OS"));
    assert_eq!(detail.value.as_deref(), Some("Linux"));
    assert_eq!(detail.extra.as_deref(), Some("extra-value"));

    let source = detail.source.as_ref().unwrap();

    assert_eq!(source.r#type.as_deref(), Some("nvt"));
    assert_eq!(source.name.as_deref(), Some("Source Name"));
    assert_eq!(source.description.as_deref(), Some("Source Description"));
}

#[test]
fn host_detail_from_dto_maps_source_and_extra() {
    let detail: dto::HostDetail = dto_from_value(json!({
        "name": "OS",
        "value": "Linux",
        "source": {
            "type": "nvt",
            "name": "Source Name",
            "description": "Source Description"
        },
        "extra": "extra-value"
    }));

    let result = host_detail_from_dto(&detail);

    assert_eq!(result.name.as_deref(), Some("OS"));
    assert_eq!(result.value.as_deref(), Some("Linux"));
    assert_eq!(result.extra.as_deref(), Some("extra-value"));

    let source = result.source.unwrap();

    assert_eq!(source.r#type.as_deref(), Some("nvt"));
    assert_eq!(source.name.as_deref(), Some("Source Name"));
    assert_eq!(source.description.as_deref(), Some("Source Description"));
}

#[test]
fn host_detail_source_from_dto_maps_all_fields() {
    let source: dto::HostDetailSource = dto_from_value(json!({
        "type": "nvt",
        "name": "Source Name",
        "description": "Source Description"
    }));

    let result = host_detail_source_from_dto(&source);

    assert_eq!(result.r#type.as_deref(), Some("nvt"));
    assert_eq!(result.name.as_deref(), Some("Source Name"));
    assert_eq!(result.description.as_deref(), Some("Source Description"));
}

#[test]
fn host_result_count_from_dto_maps_page_counts_and_deprecated_counts() {
    let count: dto::HostResultCount = dto_from_value(json!({
        "page": 10,
        "critical": {
            "page": 1
        },
        "hole": {
            "page": 2
        },
        "high": {
            "page": 3
        },
        "warning": {
            "page": 4
        },
        "medium": {
            "page": 5
        },
        "info": {
            "page": 6
        },
        "low": {
            "page": 7
        },
        "log": {
            "page": 8
        },
        "false_positive": {
            "page": 9
        }
    }));

    let result = host_result_count_from_dto(&count);

    assert_eq!(result.page.as_deref(), Some("10"));
    assert_eq!(result.critical.unwrap().page.as_deref(), Some("1"));
    assert_eq!(result.hole.unwrap().page.as_deref(), Some("2"));
    assert_eq!(result.high.unwrap().page.as_deref(), Some("3"));
    assert_eq!(result.warning.unwrap().page.as_deref(), Some("4"));
    assert_eq!(result.medium.unwrap().page.as_deref(), Some("5"));
    assert_eq!(result.info.unwrap().page.as_deref(), Some("6"));
    assert_eq!(result.low.unwrap().page.as_deref(), Some("7"));
    assert_eq!(result.log.unwrap().page.as_deref(), Some("8"));
    assert_eq!(result.false_positive.unwrap().page.as_deref(), Some("9"));
}

#[test]
fn page_count_from_dto_maps_page_to_string() {
    let count: dto::PageCount = dto_from_value(json!({
        "page": 42
    }));

    let result = page_count_from_dto(&count);

    assert_eq!(result.page.as_deref(), Some("42"));
}

#[test]
fn deprecated_page_count_from_dto_maps_page_and_sets_deprecated_to_none() {
    let count: dto::PageCount = dto_from_value(json!({
        "page": 42
    }));

    let result = deprecated_page_count_from_dto(&count);

    assert_eq!(result.page.as_deref(), Some("42"));
    assert_eq!(result.deprecated, None);
}
