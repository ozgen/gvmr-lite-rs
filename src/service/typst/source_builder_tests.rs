use std::fs;

use quick_xml::de::from_str;

use super::*;
use crate::domain::report_model::ReportEnvelope;

fn parse_report(xml: &str) -> ReportEnvelope {
    from_str(xml).unwrap()
}

fn minimal_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <results>
                </results>
            </report>
        </report>
        "#,
    )
}

fn report_with_results(results_xml: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2026-01-01T09:00:00Z</scan_start>
                <scan_end>2026-01-01T10:00:00Z</scan_end>
                <task>
                    <name>Test Task</name>
                </task>
                <results>
                    {results_xml}
                </results>
            </report>
        </report>
        "#
    ))
}

#[test]
fn new_stores_template_path() {
    let builder = TypstSourceBuilder::new("template.typ");

    assert_eq!(builder.template_path, PathBuf::from("template.typ"));
}

#[test]
fn read_template_returns_template_content() {
    let temp_dir = tempfile::tempdir().unwrap();
    let template_path = temp_dir.path().join("template.typ");

    fs::write(&template_path, "hello {{summary}}").unwrap();

    let builder = TypstSourceBuilder::new(&template_path);

    let template = builder.read_template().unwrap();

    assert_eq!(template, "hello {{summary}}");
}

#[test]
fn read_template_returns_read_template_error_when_file_is_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let template_path = temp_dir.path().join("missing.typ");

    let builder = TypstSourceBuilder::new(&template_path);

    let result = builder.read_template();

    match result {
        Err(TypstRenderError::ReadTemplate { path, .. }) => {
            assert_eq!(path, template_path);
        }
        other => panic!("expected ReadTemplate error, got {other:?}"),
    }
}

#[test]
fn build_report_source_replaces_all_template_placeholders() {
    let temp_dir = tempfile::tempdir().unwrap();
    let template_path = temp_dir.path().join("template.typ");

    fs::write(
        &template_path,
        r#"
date={{report_date}}
summary={{summary}}
overview={{overview_table}}
filter={{filter_notes}}
auth={{host_authentications}}
results={{results_per_host}}
"#,
    )
    .unwrap();

    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <severity>8.7</severity>
            <qod>
                <value>95</value>
            </qod>
            <description>Finding description</description>
            <nvt oid="1.2.3.4">
                <name>Test NVT</name>
                <tags>summary=Summary text|impact=Impact text|insight=Insight text|vuldetect=Detected remotely</tags>
                <solution type="VendorFix">Install updates</solution>
                <refs>
                    <ref type="cve" id="CVE-2026-0001"/>
                </refs>
            </nvt>
        </result>
        "#,
    );

    let builder = TypstSourceBuilder::new(&template_path);

    let source = builder.build_report_source(&report).unwrap();

    assert!(!source.contains("{{report_date}}"));
    assert!(!source.contains("{{summary}}"));
    assert!(!source.contains("{{overview_table}}"));
    assert!(!source.contains("{{filter_notes}}"));
    assert!(!source.contains("{{host_authentications}}"));
    assert!(!source.contains("{{results_per_host}}"));

    assert!(source.contains("#overview-table"));
    assert!(source.contains("#service-table"));
    assert!(source.contains("#finding-card"));
    assert!(source.contains("host-a"));
    assert!(source.contains("443/tcp"));
    assert!(source.contains("High"));
}

#[test]
fn build_report_source_returns_template_read_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let template_path = temp_dir.path().join("missing.typ");

    let report = minimal_report();
    let builder = TypstSourceBuilder::new(&template_path);

    let result = builder.build_report_source(&report);

    match result {
        Err(TypstRenderError::ReadTemplate { path, .. }) => {
            assert_eq!(path, template_path);
        }
        other => panic!("expected ReadTemplate error, got {other:?}"),
    }
}

#[test]
fn build_host_overview_table_source_returns_total_zero_row_for_empty_report() {
    let report = minimal_report();

    let source = build_host_overview_table_source(&report);

    assert!(source.starts_with("#overview-table(("));
    assert!(source.contains("[*Total*], [*0*], [*0*], [*0*], [*0*], [*0*],"));
}

#[test]
fn build_host_overview_table_source_counts_findings_by_host() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>Medium</threat>
        </result>
        <result>
            <host>host-b</host>
            <threat>Low</threat>
        </result>
        <result>
            <host>host-b</host>
            <threat>Log</threat>
        </result>
        <result>
            <host>host-b</host>
            <threat>False Positive</threat>
        </result>
        "#,
    );

    let source = build_host_overview_table_source(&report);

    assert!(source.contains("[#link(<host-host-a>)[host-a]], [1], [1], [0], [0], [0],"));
    assert!(source.contains("[#link(<host-host-b>)[host-b]], [0], [0], [1], [1], [1],"));
    assert!(source.contains("[*Total*], [*1*], [*1*], [*1*], [*1*], [*1*],"));
}

#[test]
fn build_host_authentication_source_is_currently_empty() {
    let report = minimal_report();

    let source = build_host_authentication_source(&report);

    assert_eq!(source, "");
}

#[test]
fn build_results_by_host_source_returns_empty_string_when_no_results_exist() {
    let report = minimal_report();

    let source = build_results_by_host_source(&report);

    assert_eq!(source, "");
}

#[test]
fn build_results_by_host_source_renders_hosts_and_findings() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <description>Description A</description>
            <nvt>
                <name>NVT A</name>
            </nvt>
        </result>
        <result>
            <host>host-b</host>
            <port>22/tcp</port>
            <threat>Low</threat>
            <description>Description B</description>
            <nvt>
                <name>NVT B</name>
            </nvt>
        </result>
        "#,
    );

    let source = build_results_by_host_source(&report);

    assert!(source.contains("== host-a <host-host-a>"));
    assert!(source.contains("== host-b <host-host-b>"));
    assert!(source.contains("=== 2.1.1 High 443/tcp <finding-host-a-1>"));
    assert!(source.contains("=== 2.2.1 Low 22/tcp <finding-host-b-1>"));
    assert!(source.contains("#finding-card"));
}

#[test]
fn build_single_host_section_source_includes_host_scan_window_when_available() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <host>
                    <ip>host-a</ip>
                    <start>2026-01-01T09:00:00Z</start>
                    <end>2026-01-01T10:00:00Z</end>
                </host>
                <results>
                    <result>
                        <host>host-a</host>
                        <port>443/tcp</port>
                        <threat>High</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    let grouped = results_by_host(&report);
    let results = grouped.get("host-a").unwrap();

    let source = build_single_host_section_source(&report, "host-a", results, "2.1");

    assert!(source.contains("== host-a <host-host-a>"));
    assert!(source.contains("Host scan start 2026-01-01T09:00:00Z"));
    assert!(source.contains("Host scan end 2026-01-01T10:00:00Z"));
    assert!(source.contains("#service-table"));
    assert!(source.contains("#finding-card"));
}

#[test]
fn build_host_service_table_source_renders_port_and_threat_links() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <port>80/tcp</port>
            <threat>Medium</threat>
        </result>
        "#,
    );

    let grouped = results_by_host(&report);
    let results = grouped.get("host-a").unwrap();

    let source = build_host_service_table_source("host-a", results);

    assert!(source.starts_with("#service-table(("));
    assert!(source.contains("[#link(<finding-host-a-1>)[443/tcp]], [High],"));
    assert!(source.contains("[#link(<finding-host-a-2>)[80/tcp]], [Medium],"));
}

#[test]
fn build_host_service_table_source_returns_empty_table_for_no_results() {
    let source = build_host_service_table_source("host-a", &[]);

    assert_eq!(source, "#service-table((\n))\n");
}

#[test]
fn build_finding_card_source_renders_required_fields() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <severity>8.7</severity>
            <qod>
                <value>95</value>
            </qod>
            <description>Finding description</description>
            <nvt oid="1.2.3.4">
                <name>Test NVT</name>
                <tags>summary=Summary text|impact=Impact text|insight=Insight text|vuldetect=Detected remotely</tags>
                <solution type="VendorFix">Install updates</solution>
                <refs>
                    <ref type="cve" id="CVE-2026-0001"/>
                </refs>
            </nvt>
        </result>
        "#,
    );

    let result = results_by_host(&report)["host-a"][0];

    let source = build_finding_card_source("host-a", result);

    assert!(source.contains("#finding-card("));
    assert!(source.contains(r#"threat: "High""#));
    assert!(source.contains(r#"severity: "8.7""#));
    assert!(source.contains(r#"nvt: "Test NVT""#));
    assert!(source.contains(r#"qod: "95""#));
    assert!(source.contains("Summary text"));
    assert!(source.contains("Impact text"));
    assert!(source.contains("Insight text"));
    assert!(source.contains("Detected remotely"));
    assert!(source.contains("Install updates"));
    assert!(source.contains("return to host-a"));
}

#[test]
fn build_finding_card_source_uses_empty_references_tuple_when_no_refs_exist() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <nvt>
                <name>Test NVT</name>
            </nvt>
        </result>
        "#,
    );

    let result = results_by_host(&report)["host-a"][0];

    let source = build_finding_card_source("host-a", result);

    assert!(source.contains("references: (),"));
}

#[test]
fn host_label_prefixes_sanitized_host() {
    assert_eq!(host_label("hosta"), "host-hosta");
}

#[test]
fn finding_label_prefixes_sanitized_host_and_one_based_index() {
    assert_eq!(finding_label("hosta", 0), "finding-hosta-1");
    assert_eq!(finding_label("hosta", 4), "finding-hosta-5");
}

#[test]
fn labels_sanitize_special_characters() {
    let host = "192.168.1.10";

    let host_label = host_label(host);
    let finding_label = finding_label(host, 0);

    assert!(host_label.starts_with("host-"));
    assert!(finding_label.starts_with("finding-"));
    assert!(!host_label.contains('.'));
    assert!(!finding_label.contains('.'));
}
