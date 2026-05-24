use crate::{
    domain::report_model::{ReportEnvelope, ReportResult},
    service::native_pdf::target::{ReportTargetKind, grouped_threats, image_display_name},
    xml::report_validator::parse_report_xml_flexible,
};

fn parse_report(xml: &str) -> ReportEnvelope {
    parse_report_xml_flexible(xml).expect("test report XML should parse")
}

fn first_result(report: &ReportEnvelope) -> &ReportResult {
    &report
        .report
        .results
        .as_ref()
        .expect("test report should have results")
        .result[0]
}

fn all_results(report: &ReportEnvelope) -> &[ReportResult] {
    &report
        .report
        .results
        .as_ref()
        .expect("test report should have results")
        .result
}

fn host_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <port>443/tcp</port>
                        <name>Host Finding</name>
                        <threat>High</threat>
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
                        <name>Agent Group</name>
                    </agent_group>
                </task>
                <host>
                    <ip>192.0.2.10</ip>
                    <detail>
                        <name>agentID</name>
                        <value>agent-a</value>
                    </detail>
                </host>
                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <port>443/tcp</port>
                        <name>Agent Finding</name>
                        <threat>Medium</threat>
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
                        <port>general/tcp</port>
                        <name>Container Finding</name>
                        <threat>Critical</threat>
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

fn threat_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Finding A</name>
                        <threat>Low</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <name>Finding B</name>
                        <threat>Critical</threat>
                    </result>
                    <result id="result-3">
                        <host>192.0.2.10</host>
                        <name>Finding C</name>
                        <threat>Medium</threat>
                    </result>
                    <result id="result-4">
                        <host>192.0.2.10</host>
                        <name>Finding D</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-5">
                        <host>192.0.2.10</host>
                        <name>Finding E</name>
                        <threat>Log</threat>
                    </result>
                    <result id="result-6">
                        <host>192.0.2.10</host>
                        <name>Finding F</name>
                        <threat>False Positive</threat>
                    </result>
                    <result id="result-7">
                        <host>192.0.2.10</host>
                        <name>Finding G</name>
                        <threat>False P.</threat>
                    </result>
                    <result id="result-8">
                        <host>192.0.2.10</host>
                        <name>Finding H</name>
                        <threat>Custom</threat>
                    </result>
                    <result id="result-9">
                        <host>192.0.2.10</host>
                        <name>Finding I</name>
                        <threat>High</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn from_report_detects_host_report() {
    let report = host_report();

    assert_eq!(
        ReportTargetKind::from_report(&report),
        ReportTargetKind::Host
    );
}

#[test]
fn from_report_detects_agent_report() {
    let report = agent_report();

    assert_eq!(
        ReportTargetKind::from_report(&report),
        ReportTargetKind::Agent
    );
}

#[test]
fn from_report_detects_container_image_report() {
    let report = container_image_report();

    assert_eq!(
        ReportTargetKind::from_report(&report),
        ReportTargetKind::ContainerImage
    );
}

#[test]
fn overview_column_returns_expected_labels() {
    assert_eq!(ReportTargetKind::Host.overview_column(), "Host");
    assert_eq!(ReportTargetKind::ContainerImage.overview_column(), "Image");
    assert_eq!(ReportTargetKind::Agent.overview_column(), "Agent");
}

#[test]
fn results_section_title_returns_expected_labels() {
    assert_eq!(
        ReportTargetKind::Host.results_section_title(),
        "Results per Host"
    );
    assert_eq!(
        ReportTargetKind::ContainerImage.results_section_title(),
        "Results per Image"
    );
    assert_eq!(
        ReportTargetKind::Agent.results_section_title(),
        "Results per Agent"
    );
}

#[test]
fn scan_start_label_returns_expected_labels() {
    assert_eq!(ReportTargetKind::Host.scan_start_label(), "Host scan start");
    assert_eq!(
        ReportTargetKind::ContainerImage.scan_start_label(),
        "Image scan start"
    );
    assert_eq!(
        ReportTargetKind::Agent.scan_start_label(),
        "Agent scan start"
    );
}

#[test]
fn scan_end_label_returns_expected_labels() {
    assert_eq!(ReportTargetKind::Host.scan_end_label(), "Host scan end");
    assert_eq!(
        ReportTargetKind::ContainerImage.scan_end_label(),
        "Image scan end"
    );
    assert_eq!(ReportTargetKind::Agent.scan_end_label(), "Agent scan end");
}

#[test]
fn finding_title_for_host_includes_threat_and_port() {
    let report = host_report();
    let result = first_result(&report);

    assert_eq!(ReportTargetKind::Host.finding_title(result), "High 443/tcp");
}

#[test]
fn finding_title_for_container_image_uses_only_threat() {
    let report = container_image_report();
    let result = first_result(&report);

    assert_eq!(
        ReportTargetKind::ContainerImage.finding_title(result),
        "Critical"
    );
}

#[test]
fn finding_title_for_agent_uses_only_threat() {
    let report = agent_report();
    let result = first_result(&report);

    assert_eq!(ReportTargetKind::Agent.finding_title(result), "Medium");
}

#[test]
fn is_grouped_by_threat_is_false_for_host() {
    assert!(!ReportTargetKind::Host.is_grouped_by_threat());
}

#[test]
fn is_grouped_by_threat_is_true_for_container_image_and_agent() {
    assert!(ReportTargetKind::ContainerImage.is_grouped_by_threat());
    assert!(ReportTargetKind::Agent.is_grouped_by_threat());
}

#[test]
fn image_display_name_uses_target_display_name_when_available() {
    let report = container_image_report();
    let result = first_result(&report);

    assert_eq!(image_display_name(result), "app:1.0");
}

#[test]
fn image_display_name_falls_back_to_result_host_when_target_display_name_is_missing() {
    let report = host_report();
    let result = first_result(&report);

    assert_eq!(image_display_name(result), "192.0.2.10");
}

#[test]
fn grouped_threats_orders_standard_threats_and_appends_custom_values() {
    let report = threat_report();

    assert_eq!(
        grouped_threats(all_results(&report)),
        vec![
            "Critical",
            "High",
            "Medium",
            "Low",
            "Log",
            "False Positive",
            "False P.",
            "Custom",
        ]
    );
}

#[test]
fn grouped_threats_returns_each_threat_once() {
    let report = threat_report();
    let threats = grouped_threats(all_results(&report));

    assert_eq!(threats.iter().filter(|threat| *threat == "High").count(), 1);
}

#[test]
fn grouped_threats_returns_empty_vec_for_empty_results() {
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

    assert_eq!(grouped_threats(all_results(&report)), Vec::<String>::new());
}

#[test]
fn grouped_threats_trims_threat_values() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Finding A</name>
                        <threat>  High  </threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    assert_eq!(grouped_threats(all_results(&report)), vec!["High"]);
}
