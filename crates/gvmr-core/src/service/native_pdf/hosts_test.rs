use std::collections::BTreeSet;

use fpdf::Pdf;

use crate::{
    domain::report_model::ReportEnvelope,
    service::native_pdf::{document::NativePdfDocument, target::ReportTargetKind},
    xml::report_validator::parse_report_xml_flexible,
};

use super::{
    group_results_by_threat, grouped_container_threats, ordered_threats_from_set,
    shorten_image_display_name,
};

fn parse_report(xml: &str) -> ReportEnvelope {
    parse_report_xml_flexible(xml).expect("test report XML should parse")
}

fn host_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <host>
                    <ip>192.0.2.10</ip>
                    <start>2024-01-02T03:04:05Z</start>
                    <end>2024-01-02T04:04:05Z</end>
                    <detail>
                        <name>hostname</name>
                        <value>host-a.example.test</value>
                    </detail>
                </host>

                <host>
                    <ip>192.0.2.20</ip>
                    <start>2024-01-03T03:04:05Z</start>
                    <end>2024-01-03T04:04:05Z</end>
                    <detail>
                        <name>hostname</name>
                        <value>host-b.example.test</value>
                    </detail>
                </host>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <port>80/tcp</port>
                        <name>Finding A</name>
                        <threat>High</threat>
                        <severity>8.0</severity>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <port>443/tcp</port>
                        <name>Finding B</name>
                        <threat>Medium</threat>
                        <severity>5.0</severity>
                    </result>
                    <result id="result-3">
                        <host>192.0.2.20</host>
                        <port>22/tcp</port>
                        <name>Finding C</name>
                        <threat>Low</threat>
                        <severity>2.0</severity>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn container_image_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <task>
                    <oci_image_target id="oci-target-id">
                        <name>Container Image Target</name>
                    </oci_image_target>
                </task>

                <host>
                    <ip>sha256:first-digest</ip>
                    <detail>
                        <name>Architecture</name>
                        <value>amd64</value>
                    </detail>
                </host>

                <results>
                    <result id="result-1">
                        <host>sha256:first-digest</host>
                        <name>Finding A</name>
                        <threat>Low</threat>
                        <severity>2.0</severity>
                        <oci_image>
                            <name>registry.example.test/team/app:1.0</name>
                            <digest>sha256:first-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/app</path>
                            <short_name>app:1.0</short_name>
                        </oci_image>
                    </result>
                    <result id="result-2">
                        <host>sha256:first-digest</host>
                        <name>Finding B</name>
                        <threat>Critical</threat>
                        <severity>10.0</severity>
                        <oci_image>
                            <name>registry.example.test/team/app:1.0</name>
                            <digest>sha256:first-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/app</path>
                            <short_name>app:1.0</short_name>
                        </oci_image>
                    </result>
                    <result id="result-3">
                        <host>sha256:first-digest</host>
                        <name>Finding C</name>
                        <threat>Medium</threat>
                        <severity>5.0</severity>
                        <oci_image>
                            <name>registry.example.test/team/app:1.0</name>
                            <digest>sha256:first-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/app</path>
                            <short_name>app:1.0</short_name>
                        </oci_image>
                    </result>
                    <result id="result-4">
                        <host>sha256:first-digest</host>
                        <name>Finding D</name>
                        <threat>Custom</threat>
                        <severity>1.0</severity>
                        <oci_image>
                            <name>registry.example.test/team/app:1.0</name>
                            <digest>sha256:first-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/app</path>
                            <short_name>app:1.0</short_name>
                        </oci_image>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn grouped_container_threats_returns_known_threats_in_report_order_priority() {
    let report = container_image_report();
    let results = &report.report.results.as_ref().unwrap().result;

    let threats = grouped_container_threats(results);

    assert_eq!(threats, vec!["Critical", "Medium", "Low", "Custom"]);
}

#[test]
fn grouped_container_threats_returns_each_threat_once() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results>
                    <result id="result-1">
                        <host>image</host>
                        <name>Finding A</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-2">
                        <host>image</host>
                        <name>Finding B</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-3">
                        <host>image</host>
                        <name>Finding C</name>
                        <threat>Low</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(grouped_container_threats(results), vec!["High", "Low"]);
}

#[test]
fn group_results_by_threat_orders_standard_threats_first() {
    let report = container_image_report();
    let results = &report.report.results.as_ref().unwrap().result;

    let grouped = group_results_by_threat(results);
    let threat_names = grouped
        .iter()
        .map(|(threat, _)| threat.as_str())
        .collect::<Vec<_>>();

    assert_eq!(threat_names, vec!["Critical", "Medium", "Low", "Custom"]);
}

#[test]
fn group_results_by_threat_keeps_results_inside_their_threat_group() {
    let report = container_image_report();
    let results = &report.report.results.as_ref().unwrap().result;

    let grouped = group_results_by_threat(results);

    let critical = grouped
        .iter()
        .find(|(threat, _)| threat == "Critical")
        .expect("critical group should exist");

    assert_eq!(critical.1.len(), 1);
    assert_eq!(critical.1[0].name.as_deref(), Some("Finding B"));

    let low = grouped
        .iter()
        .find(|(threat, _)| threat == "Low")
        .expect("low group should exist");

    assert_eq!(low.1.len(), 1);
    assert_eq!(low.1[0].name.as_deref(), Some("Finding A"));
}

#[test]
fn ordered_threats_from_set_orders_known_threats_before_custom_values() {
    let mut seen = BTreeSet::new();
    seen.insert("Custom".to_string());
    seen.insert("Low".to_string());
    seen.insert("Critical".to_string());
    seen.insert("Medium".to_string());
    seen.insert("Unknown".to_string());

    let ordered = ordered_threats_from_set(seen);

    assert_eq!(
        ordered,
        vec!["Critical", "Medium", "Low", "Custom", "Unknown"]
    );
}

#[test]
fn shorten_image_display_name_returns_original_when_it_fits() {
    let value = shorten_image_display_name("app:1.0", None, 34);

    assert_eq!(value, "app:1.0");
}

#[test]
fn shorten_image_display_name_appends_arch_suffix_when_it_fits() {
    let value = shorten_image_display_name("app:1.0", Some("(amd64)"), 34);

    assert_eq!(value, "app:1.0(amd64)");
}

#[test]
fn shorten_image_display_name_truncates_name_and_keeps_suffix() {
    let value = shorten_image_display_name(
        "registry.example.test/team/very-long-container-image-name:1.0",
        Some("(amd64)"),
        24,
    );

    assert!(value.contains("..."));
    assert!(value.ends_with("(amd64)"));
    assert!(value.len() <= 24);
}

#[test]
fn shorten_image_display_name_returns_suffix_when_suffix_is_too_long() {
    let value = shorten_image_display_name("app:1.0", Some("(very-long-architecture)"), 10);

    assert_eq!(value, "(very-long-architecture)");
}

#[test]
fn shorten_image_display_name_returns_ellipsis_when_name_space_is_tiny() {
    let value = shorten_image_display_name("app:1.0", None, 3);

    assert_eq!(value, "...");
}

#[test]
fn target_display_name_returns_host_target_unchanged() {
    let report = host_report();
    let document = NativePdfDocument::new(&report);
    let results = &report.report.results.as_ref().unwrap().result;

    assert!(matches!(document.target_kind, ReportTargetKind::Host));

    assert_eq!(
        document.target_display_name("192.0.2.10", results),
        "192.0.2.10"
    );
}

#[test]
fn target_display_name_returns_agent_target_unchanged() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);
    document.target_kind = ReportTargetKind::Agent;

    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(document.target_display_name("agent-a", results), "agent-a");
}

#[test]
fn target_display_name_shortens_container_image_name() {
    let report = container_image_report();
    let document = NativePdfDocument::new(&report);
    let results = &report.report.results.as_ref().unwrap().result;

    assert!(matches!(
        document.target_kind,
        ReportTargetKind::ContainerImage
    ));

    let display_name = document.target_display_name(
        "registry.example.test/team/very-long-container-image-name:1.0",
        results,
    );

    assert!(display_name.contains("..."));
}

#[test]
fn write_target_metadata_ignores_non_container_targets() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);
    let results = &report.report.results.as_ref().unwrap().result;

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_target_metadata(results);

    assert_eq!(document.pdf.get_y().to_mm(), initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_target_metadata_writes_container_image_metadata() {
    let report = container_image_report();
    let mut document = NativePdfDocument::new(&report);
    let results = &report.report.results.as_ref().unwrap().result;

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_target_metadata(results);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_target_scan_times_ignores_unknown_host_detail() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);

    let unknown_report = parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results>
                    <result id="result-1">
                        <host>192.0.2.99</host>
                        <name>Finding A</name>
                        <threat>High</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    let results = &unknown_report.report.results.as_ref().unwrap().result;

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_target_scan_times("192.0.2.99", results);

    assert_eq!(document.pdf.get_y().to_mm(), initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_target_scan_times_writes_matching_host_scan_times() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);
    let grouped = document.group_results_by_target();
    let results = grouped.get("192.0.2.10").unwrap();

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_target_scan_times("192.0.2.10", results);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_service_table_writes_host_service_table() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);
    let grouped = document.group_results_by_target();
    let results = grouped.get("192.0.2.10").unwrap();

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_service_table("192.0.2.10", results);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_service_table_writes_container_service_table() {
    let report = container_image_report();
    let mut document = NativePdfDocument::new(&report);
    let grouped = document.group_results_by_target();
    let results = grouped.get("app:1.0").unwrap();

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_service_table("app:1.0", results);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_results_per_host_returns_without_page_when_no_results_exist() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results />
            </report>
        </report>
        "#,
    );

    let mut document = NativePdfDocument::new(&report);

    document.write_results_per_host();

    assert_eq!(document.pdf.page_count(), 0);
    assert!(document.pdf.ok());
}

#[test]
fn write_results_per_host_writes_host_results_section() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_results_per_host();

    assert!(document.pdf.page_count() >= 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_results_per_host_writes_container_results_section() {
    let report = container_image_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_results_per_host();

    assert!(document.pdf.page_count() >= 1);
    assert!(document.pdf.ok());
}
