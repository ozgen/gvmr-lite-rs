use fpdf::Pdf;

use crate::{
    domain::report_model::{DeltaState, ReportEnvelope, ReportResult, ResultDelta},
    service::native_pdf::{NativePdfRenderer, document::NativePdfDocument},
    xml::report_validator::parse_report_xml_flexible,
};

use super::{
    ComplianceDisplayStatus, compliance_display_status, compliance_percentage,
    compliance_result_delta_marker, compliance_result_nvt_name, compliance_sort_rank,
    delta_state_counts, filtered_or_full, sort_compliance_results,
};

fn parse_report(xml: &str) -> ReportEnvelope {
    parse_report_xml_flexible(xml).expect("test report XML should parse")
}

fn audit_report(compliance_count: &str, compliance: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report>
            <report id="audit-report">
                {compliance_count}
                {compliance}
                <results />
            </report>
        </report>
        "#
    ))
}

fn full_audit_report() -> ReportEnvelope {
    audit_report(
        r#"
        <compliance_count>
            <full>184</full>
            <filtered>183</filtered>
            <yes>
                <full>5</full>
                <filtered>5</filtered>
            </yes>
            <no>
                <full>2</full>
                <filtered>1</filtered>
            </no>
            <incomplete>
                <full>145</full>
                <filtered>146</filtered>
            </incomplete>
            <undefined>
                <full>32</full>
                <filtered>31</filtered>
            </undefined>
        </compliance_count>
        "#,
        r#"
        <compliance>
            <full>no</full>
            <filtered>no</filtered>
        </compliance>
        "#,
    )
}

fn render_overview(report: &ReportEnvelope) {
    let mut document = NativePdfDocument::new(report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_overview_renders_authoritative_report_summary() {
    render_overview(&full_audit_report());
}

#[test]
fn filtered_values_are_preferred_over_full_values() {
    let report = full_audit_report();
    let count = report
        .report
        .compliance_count
        .as_ref()
        .expect("compliance count should exist");

    assert_eq!(count.filtered.as_deref(), Some("183"));
    assert_eq!(count.yes.as_ref().and_then(filtered_or_full), Some("5"));
    assert_eq!(count.no.as_ref().and_then(filtered_or_full), Some("1"));
    assert_eq!(
        count.incomplete.as_ref().and_then(filtered_or_full),
        Some("146")
    );
    assert_eq!(
        count.undefined.as_ref().and_then(filtered_or_full),
        Some("31")
    );
}

#[test]
fn full_values_are_used_when_filtered_values_are_absent() {
    let report = audit_report(
        r#"
        <compliance_count>
            <full>184</full>
            <yes><full>5</full></yes>
            <no><full>2</full></no>
            <incomplete><full>145</full></incomplete>
            <undefined><full>32</full></undefined>
        </compliance_count>
        "#,
        r#"<compliance><full>no</full></compliance>"#,
    );

    let count = report
        .report
        .compliance_count
        .as_ref()
        .expect("compliance count should exist");

    assert_eq!(count.full.as_deref(), Some("184"));
    assert_eq!(count.yes.as_ref().and_then(filtered_or_full), Some("5"));
    assert_eq!(count.no.as_ref().and_then(filtered_or_full), Some("2"));
    assert_eq!(
        report
            .report
            .compliance
            .as_ref()
            .and_then(|value| { value.filtered.as_deref().or(value.full.as_deref()) }),
        Some("no")
    );

    render_overview(&report);
}

#[test]
fn missing_compliance_summary_is_tolerated() {
    let report = audit_report(
        r#"<compliance_count><filtered>183</filtered></compliance_count>"#,
        "",
    );

    render_overview(&report);
}

#[test]
fn missing_compliance_count_is_tolerated() {
    let report = audit_report("", r#"<compliance><filtered>no</filtered></compliance>"#);

    render_overview(&report);
}

#[test]
fn missing_compliance_data_is_tolerated() {
    let report = audit_report("", "");

    render_overview(&report);
}

#[test]
fn delta_style_filtered_only_compliance_count_is_rendered() {
    let report = audit_report(
        r#"
        <compliance_count>
            <filtered>183</filtered>
            <yes><filtered>5</filtered></yes>
            <no><filtered>1</filtered></no>
            <incomplete><filtered>146</filtered></incomplete>
            <undefined><filtered>31</filtered></undefined>
        </compliance_count>
        "#,
        "",
    );

    render_overview(&report);
}

#[test]
fn delta_state_counts_counts_known_states_only() {
    let results = vec![
        ReportResult {
            delta: Some(ResultDelta {
                state_text: Some("changed".to_string()),
                ..ResultDelta::default()
            }),
            ..ReportResult::default()
        },
        ReportResult {
            delta: Some(ResultDelta {
                state_text: Some("new".to_string()),
                ..ResultDelta::default()
            }),
            ..ReportResult::default()
        },
        ReportResult {
            delta: Some(ResultDelta {
                state_text: Some("gone".to_string()),
                ..ResultDelta::default()
            }),
            ..ReportResult::default()
        },
        ReportResult {
            delta: Some(ResultDelta {
                state_text: Some("same".to_string()),
                ..ResultDelta::default()
            }),
            ..ReportResult::default()
        },
        ReportResult {
            delta: Some(ResultDelta {
                state_text: Some("unknown".to_string()),
                ..ResultDelta::default()
            }),
            ..ReportResult::default()
        },
        ReportResult::default(),
    ];

    assert_eq!(
        delta_state_counts(&results),
        super::DeltaStateCounts {
            changed: 1,
            new: 1,
            gone: 1,
            same: 1,
        }
    );
    assert_eq!(DeltaState::parse("unknown"), None);
}

fn delta_overview_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="current-report" type="delta">
                <compliance_count>
                    <filtered>183</filtered>
                    <yes><filtered>5</filtered></yes>
                    <no><filtered>1</filtered></no>
                    <incomplete><filtered>146</filtered></incomplete>
                    <undefined><filtered>31</filtered></undefined>
                </compliance_count>
                <results>
                    <result id="changed-1"><delta>changed</delta></result>
                    <result id="changed-2"><delta>changed</delta></result>
                    <result id="changed-3"><delta>changed</delta></result>
                    <result id="gone-1"><delta>gone</delta></result>
                    <result id="gone-2"><delta>gone</delta></result>
                    <result id="gone-3"><delta>gone</delta></result>
                    <result id="gone-4"><delta>gone</delta></result>
                    <result id="same-1"><delta>same</delta></result>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn delta_compliance_overview_renders_filtered_only_counts_and_delta_summary() {
    let report = delta_overview_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn delta_compliance_overview_tolerates_missing_compliance_and_result_deltas() {
    let report = parse_report(
        r#"
        <report>
            <report id="current-report" type="delta">
                <compliance_count><filtered>183</filtered></compliance_count>
                <results>
                    <result id="result-1" />
                </results>
            </report>
        </report>
        "#,
    );
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn delta_compliance_overview_handles_no_results() {
    let report = parse_report(
        r#"
        <report>
            <report id="current-report" type="delta">
                <compliance_count><filtered>0</filtered></compliance_count>
                <results />
            </report>
        </report>
        "#,
    );
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn normal_compliance_overview_does_not_add_delta_summary() {
    let report = full_audit_report();
    assert!(!report.report.is_delta_report());

    render_overview(&report);
}

#[test]
fn compliance_percentage_calculates_only_for_positive_totals() {
    assert_eq!(compliance_percentage(5, 183), Some(5.0 / 183.0 * 100.0));
    assert_eq!(compliance_percentage(0, 0), None);
}

#[test]
fn compliance_display_status_separates_log_from_policy_undefined() {
    let yes = ReportResult {
        compliance: Some("yes".to_string()),
        ..ReportResult::default()
    };
    let no = ReportResult {
        compliance: Some("no".to_string()),
        ..ReportResult::default()
    };
    let incomplete = ReportResult {
        compliance: Some("incomplete".to_string()),
        ..ReportResult::default()
    };
    let log = ReportResult {
        compliance: Some("undefined".to_string()),
        port: Some("22/tcp".to_string()),
        ..ReportResult::default()
    };
    let policy = ReportResult {
        compliance: Some("undefined".to_string()),
        description: Some("Compliant: UNDEFINED\nActual Value: Error".to_string()),
        ..ReportResult::default()
    };

    assert_eq!(
        compliance_display_status(&yes),
        ComplianceDisplayStatus::Yes
    );
    assert_eq!(compliance_display_status(&no), ComplianceDisplayStatus::No);
    assert_eq!(
        compliance_display_status(&incomplete),
        ComplianceDisplayStatus::Incomplete
    );
    assert_eq!(
        compliance_display_status(&log),
        ComplianceDisplayStatus::Log
    );
    assert_eq!(
        compliance_display_status(&policy),
        ComplianceDisplayStatus::Undefined
    );
    assert_eq!(log.compliance.as_deref(), Some("undefined"));
}

#[test]
fn compliance_sort_places_log_before_policy_undefined() {
    let results = [
        (
            "Undefined policy",
            Some("undefined"),
            Some("Compliant: UNDEFINED"),
        ),
        ("Log A", Some("undefined"), None),
        ("Incomplete", Some("incomplete"), None),
        ("Yes", Some("yes"), None),
        ("Log B", Some("undefined"), None),
        ("No", Some("no"), None),
    ]
    .into_iter()
    .map(|(name, compliance, description)| ReportResult {
        name: Some(name.to_string()),
        compliance: compliance.map(str::to_string),
        description: description.map(str::to_string),
        ..ReportResult::default()
    })
    .collect::<Vec<_>>();

    let names = sort_compliance_results(&results)
        .into_iter()
        .map(|result| result.name.unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "Yes",
            "No",
            "Incomplete",
            "Log A",
            "Log B",
            "Undefined policy"
        ]
    );
}

#[test]
fn compliance_sort_rank_orders_known_and_missing_states() {
    let statuses = [
        Some("yes"),
        Some("no"),
        Some("incomplete"),
        Some("undefined"),
        None,
    ];
    let results = statuses
        .into_iter()
        .map(|status| ReportResult {
            compliance: status.map(str::to_string),
            ..ReportResult::default()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        results.iter().map(compliance_sort_rank).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 3]
    );
}

#[test]
fn compliance_sort_is_stable_within_each_status_rank() {
    let results = [
        ("Incomplete A", "incomplete"),
        ("YES A", "yes"),
        ("Undefined A", "undefined"),
        ("NO A", "no"),
        ("YES B", "yes"),
        ("Incomplete B", "incomplete"),
    ]
    .into_iter()
    .map(|(name, compliance)| ReportResult {
        name: Some(name.to_string()),
        compliance: Some(compliance.to_string()),
        ..ReportResult::default()
    })
    .collect::<Vec<_>>();

    let sorted = sort_compliance_results(&results);
    let names = sorted
        .iter()
        .map(|result| result.name.as_deref().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "YES A",
            "YES B",
            "NO A",
            "Incomplete A",
            "Incomplete B",
            "Undefined A"
        ]
    );
}

fn host_summary_report(hosts: &str, full: &str, filtered: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report>
            <report id="audit-report">
                <compliance_count>
                    <full>{full}</full>
                    <filtered>{filtered}</filtered>
                    <yes><filtered>5</filtered></yes>
                    <no><filtered>1</filtered></no>
                    <incomplete><filtered>2</filtered></incomplete>
                    <undefined><filtered>3</filtered></undefined>
                </compliance_count>
                {hosts}
                <results />
            </report>
        </report>
        "#
    ))
}

#[test]
fn compliance_overview_renders_one_and_multiple_host_summaries() {
    let report = host_summary_report(
        r#"
        <host>
            <ip>192.0.2.10</ip>
            <compliance_count>
                <yes><page>2</page></yes>
                <no><page>1</page></no>
                <incomplete><page>0</page></incomplete>
                <undefined><page>1</page></undefined>
            </compliance_count>
        </host>
        <host>
            <ip>192.0.2.20</ip>
            <compliance_count>
                <yes><page>3</page></yes>
                <no><page>0</page></no>
                <incomplete><page>2</page></incomplete>
                <undefined><page>2</page></undefined>
            </compliance_count>
        </host>
        "#,
        "6",
        "5",
    );
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn compliance_overview_tolerates_hosts_without_compliance_counts() {
    let report = host_summary_report(
        r#"
        <host><ip>192.0.2.10</ip></host>
        <host>
            <ip>192.0.2.20</ip>
            <compliance_count><yes><page>1</page></yes></compliance_count>
        </host>
        "#,
        "1",
        "1",
    );
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
}

#[test]
fn compliance_overview_renders_filtering_note_when_counts_differ() {
    let report = audit_report(
        r#"<compliance_count><full>10</full><filtered>5</filtered></compliance_count>"#,
        "",
    );
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
}

#[test]
fn compliance_overview_accepts_equal_full_and_filtered_counts() {
    let report = audit_report(
        r#"<compliance_count><full>5</full><filtered>5</filtered></compliance_count>"#,
        "",
    );
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_overview();

    assert!(document.pdf.ok());
}

fn audit_results_report(results: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report>
            <report id="audit-report">
                <results>
                    {results}
                </results>
            </report>
        </report>
        "#
    ))
}

fn render_results_per_host(report: &ReportEnvelope) -> NativePdfDocument<'_> {
    let mut document = NativePdfDocument::new(report);

    document.write_compliance_results_per_host();

    document
}

#[test]
fn write_compliance_results_per_host_renders_multiple_hosts_and_statuses() {
    let report = audit_results_report(
        r#"
        <result id="result-1">
            <host>192.0.2.10</host>
            <port>general/tcp</port>
            <name>Ensure SSH root login is disabled</name>
            <compliance>no</compliance>
        </result>
        <result id="result-2">
            <host>192.0.2.10</host>
            <port>22/tcp</port>
            <name>SSH service information</name>
            <compliance>undefined</compliance>
        </result>
        <result id="result-3">
            <host>192.0.2.20</host>
            <port>general/tcp</port>
            <name>Password policy</name>
            <compliance>yes</compliance>
        </result>
        <result id="result-4">
            <host>192.0.2.20</host>
            <port>general/tcp</port>
            <name>Audit control with incomplete evidence</name>
            <compliance>incomplete</compliance>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_results_per_host_tolerates_missing_and_unknown_compliance() {
    let report = audit_results_report(
        r#"
        <result id="result-1">
            <host>192.0.2.10</host>
            <name>Missing compliance value</name>
        </result>
        <result id="result-2">
            <host>192.0.2.20</host>
            <name>Unknown compliance value</name>
            <compliance>not-applicable</compliance>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_results_per_host_wraps_long_nvt_names() {
    let report = audit_results_report(
        r#"
        <result id="result-1">
            <host>192.0.2.10</host>
            <port>general/tcp</port>
            <name>This is a deliberately long NVT name that should wrap across several lines without overflowing the compliance results table or invalidating the PDF layout</name>
            <compliance>yes</compliance>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_results_per_host_returns_cleanly_for_empty_results() {
    let report = audit_report("", "");
    let mut document = NativePdfDocument::new(&report);

    document.write_compliance_results_per_host();

    assert!(document.pdf.ok());
    assert_eq!(document.pdf.page_count(), 0);
}

#[test]
fn write_compliance_result_cards_render_structured_statuses() {
    let report = audit_results_report(
        r#"
        <result id="result-yes">
            <host>192.0.2.10</host>
            <name>YES policy result</name>
            <compliance>yes</compliance>
            <description>Compliant: YES
Actual Value: disabled
Set Point: disabled
Type of Test: config
Test: Check setting
Solution: No action required.
Notes: Example note.</description>
        </result>
        <result id="result-no">
            <host>192.0.2.10</host>
            <name>NO policy result</name>
            <compliance>no</compliance>
            <description>Compliant: NO
Actual Value: enabled
Set Point: disabled</description>
        </result>
        <result id="result-incomplete">
            <host>192.0.2.20</host>
            <name>INCOMPLETE policy result</name>
            <compliance>incomplete</compliance>
            <description>Compliant: INCOMPLETE
Actual Value: unknown</description>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_result_card_renders_undefined_informational_result() {
    let report = audit_results_report(
        r#"
        <result id="result-undefined">
            <host>192.0.2.10</host>
            <name>SSH service information</name>
            <compliance>undefined</compliance>
            <description>SSH service is available on the target.</description>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_result_card_tolerates_missing_compliance_and_description() {
    let report = audit_results_report(
        r#"
        <result id="result-missing">
            <host>192.0.2.10</host>
            <name>Missing fields</name>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_result_card_wraps_multiline_solution_and_notes() {
    let report = audit_results_report(
        r#"
        <result id="result-multiline">
            <host>192.0.2.10</host>
            <name>Multiline policy result</name>
            <compliance>no</compliance>
            <description>Compliant: NO
Actual Value: enabled
Set Point: disabled
Solution: First solution line
Second solution line
Notes: First note line
Second note line</description>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_result_card_renders_nvt_summary_qod_method_and_references() {
    let report = audit_results_report(
        r#"
        <result id="result-metadata">
            <host>192.0.2.10</host>
            <port>general/tcp</port>
            <name>Result name</name>
            <compliance>no</compliance>
            <qod><value>97</value></qod>
            <nvt oid="1.3.6.1.4.1.25623.1.0.1">
                <name>Linux: SSH PermitRootLogin</name>
                <tags>summary=Summary text|vuldetect=SSH_Cmd</tags>
                <refs>
                    <ref type="url" id="https://example.test/advisory" />
                    <ref type="cve" id="CVE-2026-0001" />
                </refs>
            </nvt>
            <description>Compliant: NO
Actual Value: enabled
Set Point: disabled</description>
        </result>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_result_cards_paginate_long_result_text() {
    let long_description = "Result detail line.\n".repeat(180);
    let report = audit_results_report(&format!(
        r#"
        <result id="result-long">
            <host>192.0.2.10</host>
            <name>Long result</name>
            <compliance>undefined</compliance>
            <description>{long_description}</description>
        </result>
        "#
    ));
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 2);
}

fn complete_audit_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="audit-report">
                <compliance_count>
                    <filtered>4</filtered>
                    <yes><filtered>1</filtered></yes>
                    <no><filtered>1</filtered></no>
                    <incomplete><filtered>1</filtered></incomplete>
                    <undefined><filtered>1</filtered></undefined>
                </compliance_count>
                <compliance><filtered>no</filtered></compliance>
                <results>
                    <result id="result-yes">
                        <host>192.0.2.10</host>
                        <port>general/tcp</port>
                        <name>Compliant policy</name>
                        <compliance>yes</compliance>
                    </result>
                    <result id="result-no">
                        <host>192.0.2.10</host>
                        <port>22/tcp</port>
                        <name>Non-compliant policy</name>
                        <compliance>no</compliance>
                    </result>
                    <result id="result-incomplete">
                        <host>192.0.2.20</host>
                        <port>general/tcp</port>
                        <name>Incomplete policy</name>
                        <compliance>incomplete</compliance>
                    </result>
                    <result id="result-undefined">
                        <host>192.0.2.20</host>
                        <port>general/tcp</port>
                        <name>Informational service</name>
                        <compliance>undefined</compliance>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn render_compliance_report_runs_complete_native_pdf_flow() {
    let report = complete_audit_report();
    let mut document = NativePdfDocument::new(&report);

    document.set_compliance_mode();
    document.prepare_toc(None);
    assert_eq!(document.toc[0].title, "Compliance Overview");
    assert_eq!(document.toc[1].title, "Results per Host");

    document.render_compliance_report();

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 3);
}

#[test]
fn native_pdf_renderer_preserves_normal_vulnerability_flow() {
    let report = audit_results_report(
        r#"
        <result id="result-1">
            <host>192.0.2.10</host>
            <port>80/tcp</port>
            <name>Normal vulnerability</name>
            <threat>High</threat>
            <severity>8.0</severity>
        </result>
        "#,
    );

    let bytes = NativePdfRenderer::new()
        .render(&report)
        .expect("normal vulnerability PDF should render");

    assert!(bytes.starts_with(b"%PDF"));
}

fn delta_audit_results_report(delta: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report>
            <report id="audit-delta-report" type="delta">
                <results>
                    <result id="current-result">
                        <host>192.0.2.10</host>
                        <port>general/tcp</port>
                        <name>Linux: SSH PermitRootLogin</name>
                        <compliance>no</compliance>
                        {delta}
                    </result>
                </results>
            </report>
        </report>
        "#
    ))
}

#[test]
fn delta_compliance_table_helpers_use_marker_column_and_plain_nvt_name() {
    let report = delta_audit_results_report("<delta>changed</delta>");
    let result = report
        .report
        .results
        .as_ref()
        .expect("delta report should include results")
        .result
        .first()
        .expect("delta report should have one result");

    assert_eq!(compliance_result_delta_marker(result, true), "~");
    assert_eq!(
        compliance_result_nvt_name(result),
        "Linux: SSH PermitRootLogin"
    );
    assert!(!compliance_result_nvt_name(result).starts_with('~'));
}

#[test]
fn delta_compliance_table_helpers_render_all_marker_states_and_blank_for_unknown() {
    let states = [
        (DeltaState::Same, "same", "="),
        (DeltaState::Changed, "changed", "~"),
        (DeltaState::New, "new", "+"),
        (DeltaState::Gone, "gone", "-"),
    ];

    for (state, xml_state, marker) in states {
        let report = delta_audit_results_report(&format!("<delta>{xml_state}</delta>"));
        let result = report
            .report
            .results
            .as_ref()
            .expect("delta report should include results")
            .result
            .first()
            .expect("delta report should have one result");

        assert_eq!(compliance_result_delta_marker(result, true), marker);
        assert_eq!(
            result.delta.as_ref().and_then(|delta| delta.state()),
            Some(state)
        );
    }

    let report = delta_audit_results_report("<delta>unknown</delta>");
    let result = report
        .report
        .results
        .as_ref()
        .expect("delta report should include results")
        .result
        .first()
        .expect("delta report should have one result");

    assert_eq!(compliance_result_delta_marker(result, true), "");
}

#[test]
fn write_compliance_delta_results_renders_same_new_and_gone() {
    for state in ["same", "new", "gone"] {
        let report = delta_audit_results_report(&format!("<delta>{state}</delta>"));
        let mut document = render_results_per_host(&report);

        assert!(document.pdf.ok());
        assert!(document.pdf.page_count() >= 1);
    }
}

#[test]
fn write_compliance_delta_results_renders_changed_previous_and_diff() {
    let report = delta_audit_results_report(
        r#"
        <delta>changed
            <result id="previous-result">
                <host>192.0.2.10</host>
                <port>general/tcp</port>
                <name>Linux: SSH PermitRootLogin</name>
                <compliance>yes</compliance>
            </result>
            <diff>@@ -1 +1 @@
-old
+new</diff>
        </delta>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_delta_results_trusts_changed_state_when_compliance_matches() {
    let report = parse_report(
        r#"
        <report>
            <report id="audit-delta-report" type="delta">
                <results>
                    <result id="current-result">
                        <host>192.0.2.10</host>
                        <name>Informational service</name>
                        <compliance>undefined</compliance>
                        <delta>changed
                            <result id="previous-result">
                                <host>192.0.2.10</host>
                                <name>Informational service</name>
                                <compliance>undefined</compliance>
                            </result>
                        </delta>
                    </result>
                </results>
            </report>
        </report>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_delta_results_handles_changed_without_previous() {
    let report = delta_audit_results_report("<delta>changed</delta>");
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}

#[test]
fn write_compliance_delta_results_handles_changed_without_diff() {
    let report = delta_audit_results_report(
        r#"
        <delta>changed
            <result id="previous-result">
                <host>192.0.2.10</host>
                <name>Linux: SSH PermitRootLogin</name>
                <compliance>yes</compliance>
            </result>
        </delta>
        "#,
    );
    let mut document = render_results_per_host(&report);

    assert!(document.pdf.ok());
    assert!(document.pdf.page_count() >= 1);
}
