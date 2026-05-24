use std::collections::BTreeMap;

use crate::{
    domain::report_model::ReportEnvelope,
    service::{
        native_pdf::{document::NativePdfDocument, grouping::FindingKey},
        report_view::ReportTargetKind,
    },
    xml::report_validator::parse_report_xml_flexible,
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
                    <detail>
                        <name>hostname</name>
                        <value>host-a.example.test</value>
                    </detail>
                </host>

                <host>
                    <ip>192.0.2.20</ip>
                    <detail>
                        <name>hostname</name>
                        <value>host-b.example.test</value>
                    </detail>
                </host>

                <results>
                    <result id="result-1">
                        <host>192.0.2.20</host>
                        <name>Finding B</name>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <name>Finding A</name>
                    </result>
                    <result id="result-3">
                        <host>192.0.2.20</host>
                        <name>Finding C</name>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn agent_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <task>
                    <agent_group id="agent-group-id">
                        <name>Test Agent Group</name>
                    </agent_group>
                </task>

                <host>
                    <ip>192.0.2.10</ip>
                    <detail>
                        <name>agentID</name>
                        <value>agent-a</value>
                    </detail>
                    <detail>
                        <name>hostname</name>
                        <value>host-a.example.test</value>
                    </detail>
                </host>

                <host>
                    <ip>192.0.2.20</ip>
                    <detail>
                        <name>agentID</name>
                        <value>agent-b</value>
                    </detail>
                    <detail>
                        <name>hostname</name>
                        <value>host-b.example.test</value>
                    </detail>
                </host>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Finding A</name>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.20</host>
                        <name>Finding B</name>
                    </result>
                    <result id="result-3">
                        <host>192.0.2.10</host>
                        <name>Finding C</name>
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

                <results>
                    <result id="result-1">
                        <host>sha256:first-digest</host>
                        <name>Finding A</name>
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
                        <oci_image>
                            <name>registry.example.test/team/app:1.0</name>
                            <digest>sha256:first-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/app</path>
                            <short_name>app:1.0</short_name>
                        </oci_image>
                    </result>
                    <result id="result-3">
                        <host>sha256:second-digest</host>
                        <name>Finding C</name>
                        <oci_image>
                            <name>registry.example.test/team/worker:2.0</name>
                            <digest>sha256:second-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/worker</path>
                            <short_name>worker:2.0</short_name>
                        </oci_image>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn finding_key_orders_by_host_then_index() {
    let mut map = BTreeMap::new();

    map.insert(
        FindingKey {
            host: "host-b".to_string(),
            index: 0,
        },
        "b0",
    );
    map.insert(
        FindingKey {
            host: "host-a".to_string(),
            index: 2,
        },
        "a2",
    );
    map.insert(
        FindingKey {
            host: "host-a".to_string(),
            index: 1,
        },
        "a1",
    );

    let values = map.values().copied().collect::<Vec<_>>();

    assert_eq!(values, vec!["a1", "a2", "b0"]);
}

#[test]
fn group_results_by_target_groups_results_by_host_target() {
    let report = host_report();
    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::Host);

    let grouped = document.group_results_by_target();

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped["192.0.2.10"].len(), 1);
    assert_eq!(grouped["192.0.2.20"].len(), 2);

    assert_eq!(grouped["192.0.2.10"][0].name.as_deref(), Some("Finding A"));
    assert_eq!(grouped["192.0.2.20"][0].name.as_deref(), Some("Finding B"));
    assert_eq!(grouped["192.0.2.20"][1].name.as_deref(), Some("Finding C"));
}

#[test]
fn target_key_for_result_uses_host_when_target_kind_is_host() {
    let report = host_report();
    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    assert_eq!(document.target, ReportTargetKind::Host);
    assert_eq!(document.target_key_for_result(result), "192.0.2.20");
}

#[test]
fn host_detail_for_result_returns_matching_host_detail() {
    let report = agent_report();
    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    let host = document
        .host_detail_for_result(result)
        .expect("host detail should exist");

    assert_eq!(host.address(), Some("192.0.2.10"));
    assert_eq!(host.agent_id(), Some("agent-a"));
}

#[test]
fn host_detail_for_result_returns_none_when_no_host_matches() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <host>
                    <ip>192.0.2.10</ip>
                </host>

                <results>
                    <result id="result-1">
                        <host>192.0.2.99</host>
                        <name>Finding A</name>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    assert!(document.host_detail_for_result(result).is_none());
}

#[test]
fn agent_id_for_result_returns_agent_id_from_matching_host_detail() {
    let report = agent_report();
    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    assert_eq!(
        document.agent_id_for_result(result).as_deref(),
        Some("agent-a")
    );
}

#[test]
fn agent_id_for_result_returns_none_when_host_detail_has_no_agent_id() {
    let report = host_report();
    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    assert_eq!(document.agent_id_for_result(result), None);
}

#[test]
fn target_key_for_result_uses_agent_id_when_target_kind_is_agent() {
    let report = agent_report();
    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    assert_eq!(document.target, ReportTargetKind::Agent);
    assert_eq!(document.target_key_for_result(result), "agent-a");
}

#[test]
fn target_key_for_result_falls_back_to_host_when_agent_id_is_missing() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);
    document.target = ReportTargetKind::Agent;

    let result = &report.report.results.as_ref().unwrap().result[0];

    assert_eq!(document.target_key_for_result(result), "192.0.2.20");
}

#[test]
fn group_results_by_target_groups_results_by_agent_id() {
    let report = agent_report();
    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::Agent);

    let grouped = document.group_results_by_target();

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped["agent-a"].len(), 2);
    assert_eq!(grouped["agent-b"].len(), 1);

    assert_eq!(grouped["agent-a"][0].name.as_deref(), Some("Finding A"));
    assert_eq!(grouped["agent-a"][1].name.as_deref(), Some("Finding C"));
    assert_eq!(grouped["agent-b"][0].name.as_deref(), Some("Finding B"));
}

#[test]
fn target_key_for_result_uses_image_display_name_when_target_kind_is_container_image() {
    let report = container_image_report();
    let document = NativePdfDocument::new(&report);
    let result = &report.report.results.as_ref().unwrap().result[0];

    assert_eq!(document.target, ReportTargetKind::ContainerImage);
    assert_eq!(document.target_key_for_result(result), "app:1.0");
}

#[test]
fn group_results_by_target_groups_results_by_container_image() {
    let report = container_image_report();
    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::ContainerImage);

    let grouped = document.group_results_by_target();

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped["app:1.0"].len(), 2);
    assert_eq!(grouped["worker:2.0"].len(), 1);

    assert_eq!(grouped["app:1.0"][0].name.as_deref(), Some("Finding A"));
    assert_eq!(grouped["app:1.0"][1].name.as_deref(), Some("Finding B"));
    assert_eq!(grouped["worker:2.0"][0].name.as_deref(), Some("Finding C"));
}
