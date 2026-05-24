use quick_xml::de::from_str;

use super::*;
use crate::domain::report_model::{ReportEnvelope, ReportResult};

fn parse_report(xml: &str) -> ReportEnvelope {
    from_str(xml).expect("test report XML should parse")
}

fn report_with_results(results_xml: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report id="outer-report" creation_time="2026-01-01T10:00:00Z">
            <task>
                <name>Outer Task</name>
            </task>
            <report id="inner-report">
                <timestamp>2026-01-02T10:00:00Z</timestamp>
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2026-01-02T09:00:00Z</scan_start>
                <scan_end>2026-01-02T10:00:00Z</scan_end>
                <task>
                    <name>Test Scan</name>
                </task>
                <host>
                    <ip>host-a</ip>
                    <start>2026-01-02T09:00:00Z</start>
                    <end>2026-01-02T10:00:00Z</end>
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
fn report_view_from_report_detects_host_target() {
    let report = report_with_results("");

    let view = ReportView::from_report(&report.report);

    assert_eq!(view.report().id.as_deref(), Some("inner-report"));
    assert_eq!(view.target_kind(), ReportTargetKind::Host);
}

#[test]
fn report_timestamp_returns_inner_report_timestamp() {
    let report = report_with_results("");

    assert_eq!(report_timestamp(&report.report), "2026-01-02T10:00:00Z");
}

#[test]
fn report_timestamp_returns_empty_string_when_inner_timestamp_is_missing() {
    let report = parse_report(
        r#"
        <report id="outer-report" creation_time="2026-01-01T10:00:00Z">
            <report id="inner-report" />
        </report>
        "#,
    );

    assert_eq!(report_timestamp(&report.report), "");
}

#[test]
fn task_name_returns_inner_report_task_name() {
    let report = report_with_results("");

    assert_eq!(task_name(&report.report), "Test Scan");
}

#[test]
fn task_name_returns_default_when_inner_task_is_missing() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <task>
                <name>Outer Task</name>
            </task>
            <report id="inner-report" />
        </report>
        "#,
    );

    assert_eq!(task_name(&report.report), "Unknown task");
}

#[test]
fn summary_text_contains_task_timezone_scan_times_and_target_name() {
    let report = report_with_results("");

    let summary = summary_text(&report.report, ReportTargetKind::Host);

    assert!(summary.contains("Test Scan"));
    assert!(summary.contains("UTC"));
    assert!(summary.contains("Fri Jan 2 09:00:00 2026 UTC"));
    assert!(summary.contains("Fri Jan 2 10:00:00 2026 UTC"));
    assert!(summary.contains("for each host"));
}

#[test]
fn report_view_summary_text_uses_detected_target() {
    let report = report_with_results("");

    let view = ReportView::from_report(&report.report);

    assert!(view.summary_text().contains("for each host"));
}

#[test]
fn all_results_returns_renderable_results_only() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <threat>High</threat>
        </result>
        <result>
            <host>host-b</host>
            <threat>Info</threat>
        </result>
        <result>
            <host>host-c</host>
            <threat>Debug</threat>
        </result>
        <result>
            <host>host-d</host>
            <threat>False Positive</threat>
        </result>
        <result>
            <host>host-e</host>
            <threat>Low</threat>
        </result>
        "#,
    );

    let results = all_results(&report.report);

    assert_eq!(results.len(), 2);
    assert_eq!(result_host(results[0]), "host-a");
    assert_eq!(result_host(results[1]), "host-e");
}

#[test]
fn should_render_result_filters_non_renderable_threats() {
    let report = report_with_results(
        r#"
        <result><threat>Info</threat></result>
        <result><threat>Debug</threat></result>
        <result><threat>False Positive</threat></result>
        <result><threat>High</threat></result>
        "#,
    );

    let results = &report.report.results.as_ref().unwrap().result;

    assert!(!should_render_result(&results[0]));
    assert!(!should_render_result(&results[1]));
    assert!(!should_render_result(&results[2]));
    assert!(should_render_result(&results[3]));
}

#[test]
fn group_results_by_host_groups_renderable_results_by_trimmed_host() {
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
        <result>
            <host>host-c</host>
            <threat>Info</threat>
        </result>
        "#,
    );

    let grouped = group_results_by_host(&report.report);
    let hosts = grouped.keys().cloned().collect::<Vec<_>>();

    assert_eq!(hosts, vec!["host-a", "host-b"]);
    assert_eq!(grouped["host-a"].len(), 1);
    assert_eq!(grouped["host-b"].len(), 2);
}

#[test]
fn build_overview_rows_adds_total_row() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <threat>Critical</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>High</threat>
        </result>
        <result>
            <host>host-b</host>
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
        "#,
    );

    let rows = build_overview_rows(&report.report, ReportTargetKind::Host);

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], vec!["host-a", "1", "1", "0", "0", "0", "0"]);
    assert_eq!(rows[1], vec!["host-b", "0", "0", "1", "1", "1", "0"]);
    assert_eq!(rows[2], vec!["Total", "1", "1", "1", "1", "1", "0"]);
}

#[test]
fn count_threat_is_case_insensitive() {
    let report = report_with_results(
        r#"
        <result><threat>High</threat></result>
        <result><threat>HIGH</threat></result>
        <result><threat>high</threat></result>
        <result><threat>Low</threat></result>
        "#,
    );

    let results = report.report.results.as_ref().unwrap().result.clone();

    assert_eq!(count_threat(&results, "high"), 3);
    assert_eq!(count_threat(&results, "LOW"), 1);
}

#[test]
fn result_helpers_return_trimmed_values() {
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

    let result = first_result(&report);

    assert_eq!(result_host(result), "example.com");
    assert_eq!(result_port(result), "443/tcp");
    assert_eq!(result_threat(result), "High");
    assert_eq!(result_severity(result), "8.7");
    assert_eq!(result_qod(result), "95");
    assert_eq!(result_name(result), "NVT Name");
}

#[test]
fn result_helpers_return_defaults_for_missing_or_blank_values() {
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

    let result = first_result(&report);

    assert_eq!(result_host(result), "unknown");
    assert_eq!(result_port(result), "general/tcp");
    assert_eq!(result_threat(result), "Log");
    assert_eq!(result_severity(result), "");
    assert_eq!(result_qod(result), "");
    assert_eq!(result_name(result), "Finding");
}

#[test]
fn result_summary_prefers_nvt_summary_tag() {
    let report = report_with_results(
        r#"
        <result>
            <description>Description fallback</description>
            <threat>High</threat>
            <nvt>
                <tags>summary=Summary tag text</tags>
            </nvt>
        </result>
        "#,
    );

    let result = first_result(&report);

    assert_eq!(result_summary(result), Some("Summary tag text".to_string()));
}

#[test]
fn result_summary_falls_back_to_description() {
    let report = report_with_results(
        r#"
        <result>
            <description>Description fallback</description>
            <threat>High</threat>
            <nvt>
                <tags>impact=Impact text</tags>
            </nvt>
        </result>
        "#,
    );

    let result = first_result(&report);

    assert_eq!(
        result_summary(result),
        Some("Description fallback".to_string())
    );
}

#[test]
fn result_tag_helpers_return_expected_values() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt>
                <tags>summary=Summary|impact=Impact|affected=Affected|insight=Insight</tags>
            </nvt>
        </result>
        "#,
    );

    let result = first_result(&report);

    assert_eq!(result_impact(result), Some("Impact".to_string()));
    assert_eq!(result_affected(result), Some("Affected".to_string()));
    assert_eq!(result_insight(result), Some("Insight".to_string()));
}

#[test]
fn result_solution_formats_solution_type_and_text() {
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

    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(
        result_solution(&results[0]),
        Some("Solution type: VendorFix\nInstall updates".to_string())
    );
    assert_eq!(
        result_solution(&results[1]),
        Some("Solution type: Mitigation".to_string())
    );
    assert_eq!(
        result_solution(&results[2]),
        Some("Use a firewall".to_string())
    );
}

#[test]
fn result_solution_returns_none_when_solution_is_missing_or_empty() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt />
        </result>
        <result>
            <threat>High</threat>
            <nvt>
                <solution></solution>
            </nvt>
        </result>
        "#,
    );

    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(result_solution(&results[0]), None);
    assert_eq!(result_solution(&results[1]), None);
}

#[test]
fn result_references_formats_typed_and_untyped_references() {
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

    let result = first_result(&report);

    assert_eq!(
        result_references(result),
        vec!["cve: CVE-2026-0001".to_string(), "BID-123".to_string()]
    );
}

#[test]
fn nvt_tag_finds_key_case_insensitively_and_trims_value() {
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

    let result = first_result(&report);

    assert_eq!(
        nvt_tag(result, "vuldetect"),
        Some("Detected remotely".to_string())
    );
}

#[test]
fn nvt_tag_returns_none_for_missing_or_empty_value() {
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

    let result = first_result(&report);

    assert_eq!(nvt_tag(result, "vuldetect"), None);
    assert_eq!(nvt_tag(result, "missing"), None);
}

#[test]
fn detection_method_combines_vuldetect_name_and_oid() {
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

    let result = first_result(&report);

    assert_eq!(
        detection_method(result),
        Some("Detected by version check\nDetails: Test NVT\nOID: 1.2.3.4".to_string())
    );
}

#[test]
fn detection_method_returns_none_when_nvt_has_no_details() {
    let report = report_with_results(
        r#"
        <result>
            <threat>High</threat>
            <nvt />
        </result>
        "#,
    );

    let result = first_result(&report);

    assert_eq!(detection_method(result), None);
}

#[test]
fn grouped_threats_returns_known_threats_in_priority_order_then_custom() {
    let report = report_with_results(
        r#"
        <result><threat>Low</threat></result>
        <result><threat>Critical</threat></result>
        <result><threat>Custom</threat></result>
        <result><threat>Medium</threat></result>
        <result><threat>Low</threat></result>
        "#,
    );

    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(
        grouped_threats(results),
        vec!["Critical", "Medium", "Low", "Custom"]
    );
}

#[test]
fn image_display_name_prefers_target_display_name_and_falls_back_to_host() {
    let report = report_with_results(
        r#"
        <result>
            <host>sha256:digest</host>
            <threat>High</threat>
            <oci_image>
                <short_name>app:1.0</short_name>
            </oci_image>
        </result>
        <result>
            <host>fallback-host</host>
            <threat>High</threat>
        </result>
        "#,
    );

    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(image_display_name(&results[0]), "app:1.0");
    assert_eq!(image_display_name(&results[1]), "fallback-host");
}

#[test]
fn filter_keyword_value_returns_matching_keyword_value_case_insensitively() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report">
                <filters>
                    <keywords>
                        <keyword>
                            <column>autofp</column>
                            <value>1</value>
                        </keyword>
                        <keyword>
                            <column>min_qod</column>
                            <value>80</value>
                        </keyword>
                    </keywords>
                </filters>
            </report>
        </report>
        "#,
    );

    assert_eq!(
        filter_keyword_value(&report.report, "AUTOFP").as_deref(),
        Some("1")
    );
    assert_eq!(
        filter_keyword_value(&report.report, "min_qod").as_deref(),
        Some("80")
    );
}

#[test]
fn filter_keyword_value_returns_none_for_missing_keyword() {
    let report = report_with_results("");

    assert_eq!(filter_keyword_value(&report.report, "missing"), None);
}

#[test]
fn build_filter_summary_text_uses_filter_keyword_values() {
    let report = parse_report(
        r#"
        <report>
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
                            <column>levels</column>
                            <value>chm</value>
                        </keyword>
                        <keyword>
                            <column>min_qod</column>
                            <value>80</value>
                        </keyword>
                    </keywords>
                </filters>
                <result_count>
                    <full>10</full>
                    <filtered>6</filtered>
                </result_count>
                <results start="3">
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

    let text = build_filter_summary_text(&report.report, ReportTargetKind::Host);

    assert!(text.contains("Vendor security updates are trusted, using full CVE matching."));
    assert!(text.contains(
        "Overrides are on. When a result has an override, this report uses the threat of the override."
    ));
    assert!(text.contains("Information on overrides is excluded from the report."));
    assert!(text.contains("Notes are excluded from the report."));
    assert!(text.contains("It only lists hosts that produced issues."));
    assert!(text.contains("It shows issues that contain the search phrase \"ssh\"."));
    assert!(text.contains("Issues with the threat level \"Low\" are not shown."));
    assert!(text.contains("Issues with the threat level \"Log\" are not shown."));
    assert!(text.contains("Only results with a minimum QoD of 80 are shown."));
    assert!(text.contains(
        "This report contains results 3 to 4 of the 6 results selected by the filtering described above."
    ));
}

#[test]
fn result_count_summary_text_reports_zero_results() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report">
                <result_count>
                    <full>0</full>
                    <filtered>0</filtered>
                </result_count>
                <results />
            </report>
        </report>
        "#,
    );

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains 0 results. Before filtering there were 0 results."
    );
}

#[test]
fn result_count_summary_text_reports_single_result_position() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report">
                <result_count>
                    <full>5</full>
                    <filtered>5</filtered>
                </result_count>
                <results start="4">
                    <result>
                        <host>host-a</host>
                        <threat>High</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains result 4 of the 5 results selected by the filtering above. Before filtering there were 5 results."
    );
}

#[test]
fn result_count_summary_text_reports_all_filtered_results() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report">
                <result_count>
                    <full>8</full>
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

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains all 2 results selected by the filtering described above. Before filtering there were 8 results."
    );
}

#[test]
fn host_scan_window_returns_matching_start_and_end() {
    let report = report_with_results("");

    assert_eq!(
        host_scan_window(&report.report, "host-a"),
        Some((
            Some("2026-01-02T09:00:00Z".to_string()),
            Some("2026-01-02T10:00:00Z".to_string())
        ))
    );
}

#[test]
fn host_scan_window_returns_none_when_host_is_missing() {
    let report = report_with_results("");

    assert_eq!(host_scan_window(&report.report, "missing-host"), None);
}

#[test]
fn format_report_date_formats_rfc3339_date() {
    assert_eq!(
        format_report_date("2026-01-02T10:00:00Z"),
        "January 2, 2026"
    );
}

#[test]
fn format_report_date_falls_back_to_clean_text_for_invalid_date() {
    assert_eq!(format_report_date("bad\u{0000}date"), "baddate");
}

#[test]
fn format_summary_datetime_formats_as_utc_summary_text() {
    assert_eq!(
        format_summary_datetime("2026-01-02T10:00:00Z"),
        "Fri Jan 2 10:00:00 2026 UTC"
    );
}

#[test]
fn format_summary_datetime_falls_back_to_clean_text_for_invalid_date() {
    assert_eq!(format_summary_datetime("bad\u{0000}date"), "baddate");
}

fn agent_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
                <timestamp>2026-01-02T10:00:00Z</timestamp>
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2026-01-02T09:00:00Z</scan_start>
                <scan_end>2026-01-02T10:00:00Z</scan_end>

                <task>
                    <name>Agent Scan</name>
                    <agent_group id="agent-group-id">
                        <name>Linux Agents</name>
                    </agent_group>
                </task>

                <filters>
                    <keywords>
                        <keyword>
                            <column>result_hosts_only</column>
                            <value>1</value>
                        </keyword>
                    </keywords>
                </filters>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Agent Finding A</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.20</host>
                        <name>Agent Finding B</name>
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
        <report id="outer-report">
            <report id="inner-report">
                <timestamp>2026-01-02T10:00:00Z</timestamp>
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2026-01-02T09:00:00Z</scan_start>
                <scan_end>2026-01-02T10:00:00Z</scan_end>

                <task>
                    <name>Container Image Scan</name>
                    <oci_image_target id="oci-target-id">
                        <name>Container Image Target</name>
                    </oci_image_target>
                </task>

                <filters>
                    <keywords>
                        <keyword>
                            <column>result_hosts_only</column>
                            <value>1</value>
                        </keyword>
                    </keywords>
                </filters>

                <results>
                    <result id="result-1">
                        <host>sha256:first-digest</host>
                        <name>Image Finding A</name>
                        <threat>Critical</threat>
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
                        <name>Image Finding B</name>
                        <threat>Low</threat>
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
                        <name>Image Finding C</name>
                        <threat>High</threat>
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
fn report_target_kind_detects_agent_report() {
    let report = agent_report();

    assert_eq!(
        ReportTargetKind::from_report(&report.report),
        ReportTargetKind::Agent
    );

    let view = ReportView::from_report(&report.report);

    assert_eq!(view.target_kind(), ReportTargetKind::Agent);
    assert_eq!(view.overview_column(), "Agent");
    assert_eq!(view.results_section_title(), "Results per Agent");
    assert_eq!(view.scan_start_label(), "Agent scan start");
    assert_eq!(view.scan_end_label(), "Agent scan end");
}

#[test]
fn report_target_kind_detects_container_image_report() {
    let report = container_image_report();

    assert_eq!(
        ReportTargetKind::from_report(&report.report),
        ReportTargetKind::ContainerImage
    );

    let view = ReportView::from_report(&report.report);

    assert_eq!(view.target_kind(), ReportTargetKind::ContainerImage);
    assert_eq!(view.overview_column(), "Image");
    assert_eq!(view.results_section_title(), "Results per Image");
    assert_eq!(view.scan_start_label(), "Image scan start");
    assert_eq!(view.scan_end_label(), "Image scan end");
}

#[test]
fn summary_text_uses_agent_wording_for_agent_report() {
    let report = agent_report();

    let view = ReportView::from_report(&report.report);
    let summary = view.summary_text();

    assert!(summary.contains("Agent Scan"));
    assert!(summary.contains("for each agent"));
}

#[test]
fn summary_text_uses_image_wording_for_container_image_report() {
    let report = container_image_report();

    let view = ReportView::from_report(&report.report);
    let summary = view.summary_text();

    assert!(summary.contains("Container Image Scan"));
    assert!(summary.contains("for each image"));
}

#[test]
fn filter_summary_text_uses_agent_wording_for_result_hosts_only() {
    let report = agent_report();

    let text = build_filter_summary_text(&report.report, ReportTargetKind::Agent);

    assert!(text.contains("It only lists agents that produced issues."));
}

#[test]
fn filter_summary_text_uses_image_wording_for_result_hosts_only() {
    let report = container_image_report();

    let text = build_filter_summary_text(&report.report, ReportTargetKind::ContainerImage);

    assert!(text.contains("It only lists images that produced issues."));
}

#[test]
fn group_results_by_target_groups_container_images_by_display_name() {
    let report = container_image_report();

    let grouped = group_results_by_target(&report.report, ReportTargetKind::ContainerImage);

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped["app:1.0"].len(), 2);
    assert_eq!(grouped["worker:2.0"].len(), 1);
}

#[test]
fn build_overview_rows_uses_container_image_display_names() {
    let report = container_image_report();

    let rows = build_overview_rows(&report.report, ReportTargetKind::ContainerImage);

    assert_eq!(rows.len(), 3);

    assert_eq!(rows[0], vec!["app:1.0", "1", "0", "0", "1", "0", "0"]);
    assert_eq!(rows[1], vec!["worker:2.0", "0", "1", "0", "0", "0", "0"]);
    assert_eq!(rows[2], vec!["Total", "1", "1", "0", "1", "0", "0"]);
}

#[test]
fn result_target_name_uses_host_for_agent_results() {
    let report = agent_report();
    let result = first_result(&report);

    assert_eq!(
        result_target_name(result, ReportTargetKind::Agent),
        "192.0.2.10"
    );
}

#[test]
fn result_target_name_uses_image_display_name_for_container_image_results() {
    let report = container_image_report();
    let result = first_result(&report);

    assert_eq!(
        result_target_name(result, ReportTargetKind::ContainerImage),
        "app:1.0"
    );
}

#[test]
fn image_display_name_falls_back_to_host_when_image_metadata_is_missing() {
    let report = report_with_results(
        r#"
        <result>
            <host>sha256:fallback-digest</host>
            <name>Fallback Image Finding</name>
            <threat>High</threat>
        </result>
        "#,
    );

    let result = first_result(&report);

    assert_eq!(image_display_name(result), "sha256:fallback-digest");
}

#[test]
fn finding_title_uses_only_threat_for_agent_and_container_image() {
    let agent = agent_report();
    let agent_result = first_result(&agent);

    assert_eq!(ReportTargetKind::Agent.finding_title(agent_result), "High");

    let container = container_image_report();
    let container_result = first_result(&container);

    assert_eq!(
        ReportTargetKind::ContainerImage.finding_title(container_result),
        "Critical"
    );
}

#[test]
fn finding_title_uses_threat_and_port_for_host_report() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <name>Host Finding</name>
            <threat>High</threat>
        </result>
        "#,
    );

    let result = first_result(&report);

    assert_eq!(ReportTargetKind::Host.finding_title(result), "High 443/tcp");
}

#[test]
fn grouped_threats_orders_agent_or_container_threat_groups() {
    let report = container_image_report();
    let results = &report.report.results.as_ref().unwrap().result;

    assert_eq!(grouped_threats(results), vec!["Critical", "High", "Low"]);
}

#[test]
fn report_view_all_results_returns_only_renderable_results() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <name>High Finding</name>
            <threat>High</threat>
        </result>
        <result>
            <host>host-b</host>
            <name>Info Finding</name>
            <threat>Info</threat>
        </result>
        <result>
            <host>host-c</host>
            <name>Low Finding</name>
            <threat>Low</threat>
        </result>
        <result>
            <host>host-d</host>
            <name>False Positive Finding</name>
            <threat>False Positive</threat>
        </result>
        "#,
    );

    let view = ReportView::from_report(&report.report);

    let results = view.all_results();

    assert_eq!(results.len(), 2);
    assert_eq!(result_host(results[0]), "host-a");
    assert_eq!(result_name(results[0]), "High Finding");
    assert_eq!(result_host(results[1]), "host-c");
    assert_eq!(result_name(results[1]), "Low Finding");
}

#[test]
fn report_view_grouped_results_by_target_groups_host_results() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-b</host>
            <name>Finding B1</name>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <name>Finding A1</name>
            <threat>Medium</threat>
        </result>
        <result>
            <host>host-b</host>
            <name>Finding B2</name>
            <threat>Low</threat>
        </result>
        "#,
    );

    let view = ReportView::from_report(&report.report);

    let grouped = view.grouped_results_by_target();

    assert_eq!(view.target_kind(), ReportTargetKind::Host);
    assert_eq!(grouped.len(), 2);

    assert_eq!(grouped["host-a"].len(), 1);
    assert_eq!(grouped["host-a"][0].name.as_deref(), Some("Finding A1"));

    assert_eq!(grouped["host-b"].len(), 2);
    assert_eq!(grouped["host-b"][0].name.as_deref(), Some("Finding B1"));
    assert_eq!(grouped["host-b"][1].name.as_deref(), Some("Finding B2"));
}

#[test]
fn report_view_grouped_results_by_target_groups_container_image_results() {
    let report = container_image_report();

    let view = ReportView::from_report(&report.report);

    let grouped = view.grouped_results_by_target();

    assert_eq!(view.target_kind(), ReportTargetKind::ContainerImage);
    assert_eq!(grouped.len(), 2);

    assert_eq!(grouped["app:1.0"].len(), 2);
    assert_eq!(grouped["worker:2.0"].len(), 1);
}

#[test]
fn report_view_overview_rows_returns_host_rows_and_total() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <name>Critical Finding</name>
            <threat>Critical</threat>
        </result>
        <result>
            <host>host-a</host>
            <name>High Finding</name>
            <threat>High</threat>
        </result>
        <result>
            <host>host-b</host>
            <name>Medium Finding</name>
            <threat>Medium</threat>
        </result>
        <result>
            <host>host-b</host>
            <name>Low Finding</name>
            <threat>Low</threat>
        </result>
        <result>
            <host>host-b</host>
            <name>Log Finding</name>
            <threat>Log</threat>
        </result>
        "#,
    );

    let view = ReportView::from_report(&report.report);

    let rows = view.overview_rows();

    assert_eq!(view.target_kind(), ReportTargetKind::Host);
    assert_eq!(rows.len(), 3);

    assert_eq!(rows[0], vec!["host-a", "1", "1", "0", "0", "0", "0"]);
    assert_eq!(rows[1], vec!["host-b", "0", "0", "1", "1", "1", "0"]);
    assert_eq!(rows[2], vec!["Total", "1", "1", "1", "1", "1", "0"]);
}

#[test]
fn report_view_overview_rows_returns_container_image_rows_and_total() {
    let report = container_image_report();

    let view = ReportView::from_report(&report.report);

    let rows = view.overview_rows();

    assert_eq!(view.target_kind(), ReportTargetKind::ContainerImage);
    assert_eq!(rows.len(), 3);

    assert_eq!(rows[0], vec!["app:1.0", "1", "0", "0", "1", "0", "0"]);
    assert_eq!(rows[1], vec!["worker:2.0", "0", "1", "0", "0", "0", "0"]);
    assert_eq!(rows[2], vec!["Total", "1", "1", "0", "1", "0", "0"]);
}
