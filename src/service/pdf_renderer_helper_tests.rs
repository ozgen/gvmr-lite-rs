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
            <report id="inner-report" timestamp="2026-01-02T10:00:00Z">
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
                <scan_start>2026-01-02T09:00:00Z</scan_start>
                <scan_end>2026-01-02T10:00:00Z</scan_end>
                <task>
                    <name>Test Scan</name>
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
fn all_results_filters_info_debug_and_false_positive() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>Info</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>Debug</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>False Positive</threat>
        </result>
        <result>
            <host>host-a</host>
            <threat>Log</threat>
        </result>
        "#,
    );

    let results = all_results(&report);

    assert_eq!(results.len(), 2);
    assert_eq!(result_threat(results[0]), "High");
    assert_eq!(result_threat(results[1]), "Log");
}

#[test]
fn all_results_returns_empty_vec_when_results_are_missing() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
            </report>
        </report>
        "#,
    );

    let results = all_results(&report);

    assert!(results.is_empty());
}

#[test]
fn should_render_result_rejects_non_renderable_threats_case_insensitively() {
    let report = report_with_results(
        r#"
        <result><threat>info</threat></result>
        <result><threat>DEBUG</threat></result>
        <result><threat>false positive</threat></result>
        <result><threat>High</threat></result>
        "#,
    );

    let results = report.report.results.as_ref().unwrap();

    assert!(!should_render_result(&results.result[0]));
    assert!(!should_render_result(&results.result[1]));
    assert!(!should_render_result(&results.result[2]));
    assert!(should_render_result(&results.result[3]));
}

#[test]
fn group_results_by_host_groups_renderable_results_and_uses_sorted_hosts() {
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

    let grouped = group_results_by_host(&report);
    let hosts = grouped.keys().cloned().collect::<Vec<_>>();

    assert_eq!(hosts, vec!["host-a", "host-b"]);
    assert_eq!(grouped["host-a"].len(), 1);
    assert_eq!(grouped["host-b"].len(), 2);
}

#[test]
fn build_overview_rows_counts_threats_per_host_and_total() {
    let report = report_with_results(
        r#"
        <result><host>host-a</host><threat>Critical</threat></result>
        <result><host>host-a</host><threat>High</threat></result>
        <result><host>host-a</host><threat>High</threat></result>
        <result><host>host-b</host><threat>Medium</threat></result>
        <result><host>host-b</host><threat>Low</threat></result>
        <result><host>host-b</host><threat>Log</threat></result>
        <result><host>host-b</host><threat>Info</threat></result>
        "#,
    );

    let rows = build_overview_rows(&report);

    assert_eq!(
        rows,
        vec![
            vec!["host-a", "1", "2", "0", "0", "0"],
            vec!["host-b", "0", "0", "1", "1", "1"],
            vec!["Total", "1", "2", "1", "1", "1"],
        ]
    );
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

    let results = all_results(&report)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();

    assert_eq!(count_threat(&results, "high"), 3);
    assert_eq!(count_threat(&results, "LOW"), 1);
}

#[test]
fn result_helpers_return_trimmed_values() {
    let report = report_with_results(
        r#"
        <result>
            <name>  Fallback Name  </name>
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

    let result = all_results(&report)[0];

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

    let result = all_results(&report)[0];

    assert_eq!(result_host(result), "unknown");
    assert_eq!(result_port(result), "general/tcp");
    assert_eq!(result_threat(result), "Log");
    assert_eq!(result_severity(result), "");
    assert_eq!(result_qod(result), "");
    assert_eq!(result_name(result), "Finding");
}

#[test]
fn result_name_prefers_nvt_name_over_result_name() {
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

    let result = all_results(&report)[0];

    assert_eq!(result_name(result), "NVT Name");
}

#[test]
fn result_name_falls_back_to_result_name_when_nvt_name_is_missing() {
    let report = report_with_results(
        r#"
        <result>
            <name>Result Name</name>
            <threat>High</threat>
        </result>
        "#,
    );

    let result = all_results(&report)[0];

    assert_eq!(result_name(result), "Result Name");
}

#[test]
fn result_solution_returns_none_when_solution_is_missing_or_empty() {
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

    let results = all_results(&report);

    assert_eq!(result_solution(results[0]), None);
    assert_eq!(result_solution(results[1]), None);
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

    let results = all_results(&report);

    assert_eq!(
        result_solution(results[0]),
        Some("Solution type: VendorFix\nInstall updates".to_string())
    );
    assert_eq!(
        result_solution(results[1]),
        Some("Solution type: Mitigation".to_string())
    );
    assert_eq!(
        result_solution(results[2]),
        Some("Use a firewall".to_string())
    );
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

    let result = all_results(&report)[0];

    assert_eq!(
        result_references(result),
        vec!["cve: CVE-2026-0001".to_string(), "BID-123".to_string()]
    );
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

    let result = all_results(&report)[0];

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
            <nvt></nvt>
        </result>
        "#,
    );

    let result = all_results(&report)[0];

    assert_eq!(detection_method(result), None);
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

    let result = all_results(&report)[0];

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

    let result = all_results(&report)[0];

    assert_eq!(nvt_tag(result, "vuldetect"), None);
    assert_eq!(nvt_tag(result, "missing"), None);
}

#[test]
fn task_name_prefers_inner_report_task_name() {
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

    assert_eq!(task_name(&report), "Inner Task");
}

#[test]
fn task_name_falls_back_to_outer_task_name() {
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

    assert_eq!(task_name(&report), "Outer Task");
}

#[test]
fn task_name_returns_default_when_missing() {
    let report = parse_report(
        r#"
        <report id="outer-report">
            <report id="inner-report">
            </report>
        </report>
        "#,
    );

    assert_eq!(task_name(&report), "Unknown task");
}

#[test]
fn summary_text_contains_task_timezone_and_scan_times() {
    let report = report_with_results("");

    let summary = summary_text(&report);

    assert!(summary.contains("Test Scan"));
    assert!(summary.contains("UTC"));
    assert!(summary.contains("2026-01-02T09:00:00Z"));
    assert!(summary.contains("2026-01-02T10:00:00Z"));
}

#[test]
fn severity_color_returns_expected_rgb_values() {
    assert_eq!(severity_color("critical"), (139, 0, 0));
    assert_eq!(severity_color("High"), (220, 20, 60));
    assert_eq!(severity_color(" medium "), (255, 140, 0));
    assert_eq!(severity_color("low"), (80, 160, 200));
    assert_eq!(severity_color("log"), (30, 144, 255));
    assert_eq!(severity_color("unknown"), (100, 100, 100));
}

#[test]
fn estimate_line_count_returns_zero_for_blank_text() {
    assert_eq!(estimate_line_count("", 80), 0);
    assert_eq!(estimate_line_count("   \n\t", 80), 0);
}

#[test]
fn estimate_line_count_counts_non_empty_text() {
    assert_eq!(estimate_line_count("abc", 10), 1);
    assert_eq!(estimate_line_count("abc\ndef", 10), 2);
}

#[test]
fn truncate_text_returns_original_when_within_limit() {
    assert_eq!(truncate_text("hello", 5), "hello");
}

#[test]
fn truncate_text_truncates_by_chars_not_bytes() {
    assert_eq!(truncate_text("äöühello", 3), "äöü\n\n[truncated]");
}

#[test]
fn clean_text_removes_null_and_control_chars_and_normalizes_unicode_punctuation() {
    let text = "hello\u{0000}\u{0007} “world” ‘test’ – dash — more …\n\t";

    let cleaned = clean_text(text);

    assert_eq!(cleaned, "hello \"world\" 'test' - dash - more ...\n\t");
}

#[test]
fn wrap_text_wraps_words_without_exceeding_limit_when_possible() {
    let lines = wrap_text("one two three four", 8);

    assert_eq!(lines, vec!["one two", "three", "four"]);
}

#[test]
fn wrap_text_preserves_empty_paragraphs() {
    let lines = wrap_text("one\n\nthree", 10);

    assert_eq!(lines, vec!["one", "", "three"]);
}

#[test]
fn wrap_text_keeps_long_word_on_own_line() {
    let lines = wrap_text("short veryverylongword end", 5);

    assert_eq!(lines, vec!["short", "veryverylongword", "end"]);
}

#[test]
fn group_results_by_host_limits_to_max_findings() {
    let mut results_xml = String::new();

    for index in 0..(MAX_FINDINGS + 10) {
        results_xml.push_str(&format!(
            r#"
            <result>
                <host>host-{index}</host>
                <threat>High</threat>
            </result>
            "#
        ));
    }

    let report = report_with_results(&results_xml);

    let grouped = group_results_by_host(&report);
    let total = grouped.values().map(Vec::len).sum::<usize>();

    assert_eq!(total, MAX_FINDINGS);
}
