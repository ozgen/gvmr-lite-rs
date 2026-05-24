use std::{fs, path::PathBuf};

use quick_xml::de::from_str;

use super::*;
use crate::{
    domain::report_model::{ReportEnvelope, ReportResult},
    service::typst::error::TypstRenderError,
};

fn parse_report(xml: &str) -> ReportEnvelope {
    from_str(xml).expect("test report XML should parse")
}

fn minimal_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <results />
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
                <timestamp>2026-01-01T10:00:00Z</timestamp>
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2026-01-01T09:00:00Z</scan_start>
                <scan_end>2026-01-01T10:00:00Z</scan_end>
                <task>
                    <name>Test Task</name>
                </task>
                <host>
                    <ip>host-a</ip>
                    <start>2026-01-01T09:00:00Z</start>
                    <end>2026-01-01T10:00:00Z</end>
                </host>
                <results>
                    {results_xml}
                </results>
            </report>
        </report>
        "#
    ))
}

fn first_result(report: &ReportEnvelope) -> &ReportResult {
    &report
        .report
        .results
        .as_ref()
        .expect("test report should have results")
        .result[0]
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
                <tags>summary=Summary text|impact=Impact text|affected=Affected text|insight=Insight text|vuldetect=Detected remotely</tags>
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
    assert!(source.contains("January 1, 2026"));
    assert!(source.contains("Test Task"));
    assert!(source.contains("Only results with a minimum QoD of 70 are shown."));
    assert!(source.contains("host-a"));
    assert!(source.contains("443/tcp"));
    assert!(source.contains("High"));
    assert!(source.contains("Affected text"));
}

#[test]
fn build_report_source_uses_shared_filter_summary_text() {
    let temp_dir = tempfile::tempdir().unwrap();
    let template_path = temp_dir.path().join("template.typ");

    fs::write(&template_path, "{{filter_notes}}").unwrap();

    let report = parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <filters>
                    <term>ssh</term>
                    <keywords>
                        <keyword>
                            <column>autofp</column>
                            <value>1</value>
                        </keyword>
                        <keyword>
                            <column>apply_overrides</column>
                            <value>1</value>
                        </keyword>
                        <keyword>
                            <column>overrides</column>
                            <value>0</value>
                        </keyword>
                        <keyword>
                            <column>notes</column>
                            <value>0</value>
                        </keyword>
                        <keyword>
                            <column>result_hosts_only</column>
                            <value>1</value>
                        </keyword>
                        <keyword>
                            <column>min_qod</column>
                            <value>80</value>
                        </keyword>
                    </keywords>
                </filters>
                <result_count>
                    <full>10</full>
                    <filtered>2</filtered>
                </result_count>
                <results>
                    <result>
                        <host>host-a</host>
                        <threat>High</threat>
                    </result>
                    <result>
                        <host>host-b</host>
                        <threat>Medium</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    let builder = TypstSourceBuilder::new(&template_path);

    let source = builder.build_report_source(&report).unwrap();

    assert!(source.contains("Vendor security updates are trusted, using full CVE matching."));
    assert!(source.contains("Overrides are on."));
    assert!(source.contains("Information on overrides is excluded from the report."));
    assert!(source.contains("Notes are excluded from the report."));
    assert!(source.contains("It only lists hosts that produced issues."));
    assert!(source.contains("search phrase"));
    assert!(source.contains("ssh"));
    assert!(source.contains("minimum QoD of 80"));
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
    assert!(source.contains("[#link(<host-host-b>)[host-b]], [0], [0], [1], [1], [0],"));
    assert!(source.contains("[*Total*], [*1*], [*1*], [*1*], [*1*], [*0*],"));
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
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <description>Description A</description>
        </result>
        "#,
    );

    let results = report.report.results.as_ref().unwrap().result.clone();

    let source = build_single_host_section_source(&report, "host-a", &results, "2.1");

    assert!(source.contains("== host-a <host-host-a>"));
    assert!(source.contains("Host scan start 2026-01-01T09:00:00Z"));
    assert!(source.contains("Host scan end 2026-01-01T10:00:00Z"));
}

#[test]
fn build_single_host_section_source_omits_host_scan_window_when_missing() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-b</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <description>Description A</description>
        </result>
        "#,
    );

    let results = report.report.results.as_ref().unwrap().result.clone();

    let source = build_single_host_section_source(&report, "host-b", &results, "2.1");

    assert!(source.contains("== host-b <host-host-b>"));
    assert!(!source.contains("Host scan start"));
    assert!(!source.contains("Host scan end"));
}

#[test]
fn build_host_service_table_source_links_ports_to_findings() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <port>22/tcp</port>
            <threat>Low</threat>
        </result>
        "#,
    );

    let results = &report.report.results.as_ref().unwrap().result;

    let source = build_host_service_table_source("host-a", results);

    assert!(source.contains("#service-table"));
    assert!(source.contains("[#link(<finding-host-a-1>)[443/tcp]], [High],"));
    assert!(source.contains("[#link(<finding-host-a-2>)[22/tcp]], [Low],"));
}

#[test]
fn build_finding_card_source_contains_result_fields() {
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
                <tags>summary=Summary text|impact=Impact text|affected=Affected text|insight=Insight text|vuldetect=Detected remotely</tags>
                <solution type="VendorFix">Install updates</solution>
                <refs>
                    <ref type="cve" id="CVE-2026-0001"/>
                    <ref type="url" id="https://example.test/advisory"/>
                </refs>
            </nvt>
        </result>
        "#,
    );

    let result = first_result(&report);

    let source = build_finding_card_source("host-a", result);

    assert!(source.contains("#finding-card"));
    assert!(source.contains("threat: \"High\""));
    assert!(source.contains("severity: \"8.7\""));
    assert!(source.contains("nvt: \"Test NVT\""));
    assert!(source.contains("qod: \"95\""));
    assert!(source.contains("detection-result: \"Finding description\""));
    assert!(source.contains("Summary text"));
    assert!(source.contains("Impact text"));
    assert!(source.contains("Affected text"));
    assert!(source.contains("Insight text"));
    assert!(source.contains("Detected remotely"));
    assert!(source.contains("Solution type: VendorFix"));
    assert!(source.contains("Install updates"));
    assert!(source.contains("cve: CVE-2026-0001"));
    assert!(source.contains("url: https://example.test/advisory"));
    assert!(source.contains("#link(<host-host-a>)[return to host-a]"));
}

#[test]
fn build_finding_card_source_uses_none_for_missing_optional_fields() {
    let report = report_with_results(
        r#"
        <result>
            <name>Test Finding</name>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <description></description>
            <nvt />
        </result>
        "#,
    );

    let result = first_result(&report);

    let source = build_finding_card_source("host-a", result);

    assert!(source.contains("summary: none"));
    assert!(source.contains("impact: none"));
    assert!(source.contains("solution: none"));
    assert!(source.contains("affected: none"));
    assert!(source.contains("insight: none"));
    assert!(source.contains("detection-method: none"));
    assert!(source.contains("references: ()"));
}

#[test]
fn host_label_sanitizes_host_value() {
    assert_eq!(host_label("192.0.2.10"), "host-192-0-2-10");
    assert_eq!(
        host_label("host_a.example.test"),
        "host-host-a-example-test"
    );
}

#[test]
fn finding_label_sanitizes_host_value_and_adds_one_based_index() {
    assert_eq!(finding_label("192.0.2.10", 0), "finding-192-0-2-10-1");
    assert_eq!(
        finding_label("host_a.example.test", 4),
        "finding-host-a-example-test-5"
    );
}
