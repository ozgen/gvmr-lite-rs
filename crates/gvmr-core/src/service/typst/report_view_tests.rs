use quick_xml::de::from_str;

use super::*;
use crate::domain::report_model::ReportEnvelope;

fn parse_report(xml: &str) -> ReportEnvelope {
    from_str(xml).unwrap()
}

fn report_with_results(results_xml: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report id="outer-report" creation_time="2026-01-01T10:00:00Z">
            <task>
                <name>Outer Task</name>
            </task>
            <report id="inner-report" timestamp="2026-01-02T10:00:00Z">
                <timezone>Europe/Berlin</timezone>
                <timezone_abbrev>CET</timezone_abbrev>
                <scan_start>2026-01-02T09:00:00Z</scan_start>
                <scan_end>2026-01-02T10:00:00Z</scan_end>
                <task>
                    <name>Inner Task</name>
                </task>
                <result_count>
                    <filtered>2</filtered>
                    <full>5</full>
                </result_count>
                <results>
                    {results_xml}
                </results>
            </report>
        </report>
        "#
    ))
}

fn minimal_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
            </report>
        </report>
        "#,
    )
}

#[test]
fn report_timestamp_returns_empty_string_when_missing() {
    let report = minimal_report();

    assert_eq!(report_timestamp(&report), "");
}

#[test]
fn report_task_name_prefers_inner_task_name() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <task>
                <name>Outer Task</name>
            </task>
            <report id="inner-report">
                <task>
                    <name>Inner Task</name>
                </task>
            </report>
        </report>
        "#,
    );

    assert_eq!(report_task_name(&report), "Inner Task");
}

#[test]
fn report_task_name_falls_back_to_outer_task_name() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <task>
                <name>Outer Task</name>
            </task>
            <report id="inner-report">
            </report>
        </report>
        "#,
    );

    assert_eq!(report_task_name(&report), "Outer Task");
}

#[test]
fn report_task_name_returns_default_when_missing_or_blank() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <task>
                <name>   </name>
            </task>
            <report id="inner-report">
                <task>
                    <name>   </name>
                </task>
            </report>
        </report>
        "#,
    );

    assert_eq!(report_task_name(&report), "Unknown task");
}

#[test]
fn build_summary_text_contains_expected_report_context() {
    let report = report_with_results("");

    let summary = build_summary_text(&report);

    assert!(summary.contains("Europe/Berlin"));
    assert!(summary.contains("CET"));
    assert!(summary.contains("Inner Task"));
    assert!(summary.contains("2026-01-02T09:00:00Z"));
    assert!(summary.contains("2026-01-02T10:00:00Z"));
}

#[test]
fn build_summary_text_uses_defaults_for_missing_fields() {
    let report = minimal_report();

    let summary = build_summary_text(&report);

    assert!(summary.contains("unknown"));
    assert!(summary.contains("Unknown task"));
}

#[test]
fn report_results_returns_inner_results_slice() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <threat>High</threat>
        </result>
        <result>
            <host>host-b</host>
            <threat>Low</threat>
        </result>
        "#,
    );

    let results = report_results(&report);

    assert_eq!(results.len(), 2);
    assert_eq!(finding_host(&results[0]), "host-a");
    assert_eq!(finding_host(&results[1]), "host-b");
}

#[test]
fn report_results_returns_empty_slice_when_results_are_missing() {
    let report = minimal_report();

    assert!(report_results(&report).is_empty());
}

#[test]
fn results_by_host_groups_results_and_sorts_hosts() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-b</host>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>Low</threat>
        </result>
        <result>
            <host>host-b</host>
            <threat>Medium</threat>
        </result>
        "#,
    );

    let grouped = results_by_host(&report);
    let hosts = grouped.keys().cloned().collect::<Vec<_>>();

    assert_eq!(hosts, vec!["host-a", "host-b"]);
    assert_eq!(grouped["host-a"].len(), 1);
    assert_eq!(grouped["host-b"].len(), 2);
}

#[test]
fn results_by_host_uses_unknown_for_missing_or_blank_host() {
    let report = report_with_results(
        r#"
        <result>
            <host>   </host>
            <threat>High</threat>
        </result>
        <result>
            <threat>Low</threat>
        </result>
        "#,
    );

    let grouped = results_by_host(&report);

    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped["unknown"].len(), 2);
}

#[test]
fn build_filter_notes_uses_filtered_and_full_counts() {
    let report = report_with_results("");

    let notes = build_filter_notes(&report);

    assert!(notes.contains("2 results"));
    assert!(notes.contains("Before filtering there were 5 results"));
}

#[test]
fn build_filter_notes_handles_missing_counts_as_empty_strings() {
    let report = minimal_report();

    let notes = build_filter_notes(&report);

    assert!(notes.contains("This report contains  results"));
    assert!(notes.contains("Before filtering there were  results"));
}

#[test]
fn finding_helpers_return_trimmed_values() {
    let report = report_with_results(
        r#"
        <result>
            <name>  Result Name  </name>
            <host>  example.com  </host>
            <port>  443/tcp  </port>
            <threat>  High  </threat>
            <severity>  8.7  </severity>
            <qod>
                <value>  95  </value>
            </qod>
            <nvt>
                <name>  NVT Name  </name>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(finding_host(result), "example.com");
    assert_eq!(finding_port(result), "443/tcp");
    assert_eq!(finding_threat(result), "High");
    assert_eq!(finding_severity(result), "8.7");
    assert_eq!(finding_qod(result), "95");
    assert_eq!(finding_name(result), "NVT Name");
}

#[test]
fn finding_helpers_return_defaults_for_missing_or_blank_values() {
    let report = report_with_results(
        r#"
        <result>
            <host>   </host>
            <port>   </port>
            <threat>   </threat>
            <severity>   </severity>
            <qod>
                <value>   </value>
            </qod>
            <name>   </name>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(finding_host(result), "unknown");
    assert_eq!(finding_port(result), "general/tcp");
    assert_eq!(finding_threat(result), "Log");
    assert_eq!(finding_severity(result), "");
    assert_eq!(finding_qod(result), "");
    assert_eq!(finding_name(result), "Finding");
}

#[test]
fn finding_name_prefers_nvt_name_over_result_name() {
    let report = report_with_results(
        r#"
        <result>
            <name>Result Name</name>
            <threat>High</threat>
            <nvt>
                <name>NVT Name</name>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(finding_name(result), "NVT Name");
}

#[test]
fn finding_name_falls_back_to_result_name_when_nvt_name_is_missing() {
    let report = report_with_results(
        r#"
        <result>
            <name>Result Name</name>
            <threat>High</threat>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(finding_name(result), "Result Name");
}

#[test]
fn finding_solution_returns_none_when_solution_is_missing_or_empty() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
            </nvt>
        </result>
        <result>
            <threat>High</threat>
            <nvt>
                <solution></solution>
            </nvt>
        </result>
        "#,
    );

    let results = report_results(&report);

    assert_eq!(finding_solution(&results[0]), None);
    assert_eq!(finding_solution(&results[1]), None);
}

#[test]
fn finding_solution_formats_type_and_text() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
                <solution type="VendorFix">Install updates</solution>
            </nvt>
        </result>
        <result>
            <threat>High</threat>
            <nvt>
                <solution type="Mitigation"></solution>
            </nvt>
        </result>
        <result>
            <threat>High</threat>
            <nvt>
                <solution>Use a firewall</solution>
            </nvt>
        </result>
        "#,
    );

    let results = report_results(&report);

    assert_eq!(
        finding_solution(&results[0]),
        Some("Solution type: VendorFix\nInstall updates".to_string())
    );
    assert_eq!(
        finding_solution(&results[1]),
        Some("Solution type: Mitigation".to_string())
    );
    assert_eq!(
        finding_solution(&results[2]),
        Some("Use a firewall".to_string())
    );
}

#[test]
fn finding_references_formats_typed_and_untyped_references() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
                <refs>
                    <ref type="cve" id="CVE-2026-0001"/>
                    <ref id="BID-123"/>
                    <ref type="url" id="   "/>
                </refs>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(
        finding_references(result),
        vec!["cve: CVE-2026-0001".to_string(), "BID-123".to_string()]
    );
}

#[test]
fn finding_references_returns_empty_vec_when_missing() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert!(finding_references(result).is_empty());
}

#[test]
fn finding_detection_method_combines_vuldetect_name_and_oid() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt oid="1.2.3.4">
                <name>Test NVT</name>
                <tags>summary=abc|vuldetect=Detected by version check|impact=high</tags>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(
        finding_detection_method(result),
        Some("Detected by version check\nDetails: Test NVT\nOID: 1.2.3.4".to_string())
    );
}

#[test]
fn finding_detection_method_returns_none_when_nvt_has_no_details() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(finding_detection_method(result), None);
}

#[test]
fn finding_nvt_tag_finds_key_case_insensitively_and_trims_value() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
                <tags>summary=abc|VULDETECT=  Detected remotely  |impact=high</tags>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(
        finding_nvt_tag(result, "vuldetect"),
        Some("Detected remotely".to_string())
    );
}

#[test]
fn finding_nvt_tag_returns_none_for_missing_or_empty_value() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
                <tags>summary=abc|vuldetect=   |impact=high</tags>
            </nvt>
        </result>
        "#,
    );

    let result = &report_results(&report)[0];

    assert_eq!(finding_nvt_tag(result, "vuldetect"), None);
    assert_eq!(finding_nvt_tag(result, "missing"), None);
}

#[test]
fn count_findings_by_threat_is_case_insensitive_and_ignores_missing_threats() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
        </result>
        <result>
            <threat> HIGH </threat>
        </result>
        <result>
            <threat>low</threat>
        </result>
        <result>
        </result>
        "#,
    );

    let results = report_results(&report).iter().collect::<Vec<_>>();

    assert_eq!(count_findings_by_threat(&results, "high"), 2);
    assert_eq!(count_findings_by_threat(&results, "LOW"), 1);
    assert_eq!(count_findings_by_threat(&results, "medium"), 0);
}

#[test]
fn host_scan_window_returns_matching_host_start_and_end() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <host>
                    <ip>192.168.1.10</ip>
                    <start>2026-01-02T09:00:00Z</start>
                    <end>2026-01-02T09:05:00Z</end>
                </host>
                <host>
                    <ip>192.168.1.20</ip>
                    <start>2026-01-02T09:10:00Z</start>
                    <end>2026-01-02T09:15:00Z</end>
                </host>
            </report>
        </report>
        "#,
    );

    assert_eq!(
        host_scan_window(&report, "192.168.1.20"),
        Some((
            Some("2026-01-02T09:10:00Z".to_string()),
            Some("2026-01-02T09:15:00Z".to_string())
        ))
    );
}

#[test]
fn host_scan_window_returns_none_for_missing_host() {
    let report = minimal_report();

    assert_eq!(host_scan_window(&report, "192.168.1.10"), None);
}
