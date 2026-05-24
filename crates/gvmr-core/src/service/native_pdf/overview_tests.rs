use fpdf::Pdf;

use crate::{
    domain::report_model::ReportEnvelope,
    service::{
        native_pdf::document::NativePdfDocument,
        report_view::{
            ReportTargetKind, build_filter_summary_text, filter_keyword_value,
            result_count_summary_text,
        },
    },
    xml::report_validator::parse_report_xml_flexible,
};
fn parse_report(xml: &str) -> ReportEnvelope {
    parse_report_xml_flexible(xml).expect("test report XML should parse")
}

fn overview_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <result_count>
                    <full>8</full>
                    <filtered>5</filtered>
                </result_count>

                <results start="2">
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Critical Finding</name>
                        <threat>Critical</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <name>High Finding</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-3">
                        <host>192.0.2.20</host>
                        <name>Medium Finding</name>
                        <threat>Medium</threat>
                    </result>
                    <result id="result-4">
                        <host>192.0.2.20</host>
                        <name>Low Finding</name>
                        <threat>Low</threat>
                    </result>
                    <result id="result-5">
                        <host>192.0.2.20</host>
                        <name>Log Finding</name>
                        <threat>Log</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn filtered_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

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
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Finding A</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.20</host>
                        <name>Finding B</name>
                        <threat>Medium</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn empty_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <result_count>
                    <full>0</full>
                    <filtered>0</filtered>
                </result_count>
                <results />
            </report>
        </report>
        "#,
    )
}

fn one_result_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <result_count>
                    <full>5</full>
                    <filtered>5</filtered>
                </result_count>
                <results start="4">
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Single Finding</name>
                        <threat>High</threat>
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
                        <name>Critical Image Finding</name>
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
                        <name>Low Image Finding</name>
                        <threat>Low</threat>
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
fn build_overview_rows_groups_by_host_and_adds_total_row() {
    let report = overview_report();
    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::Host);

    let rows = document.build_overview_rows();

    assert_eq!(rows.len(), 3);

    assert_eq!(rows[0].key, "192.0.2.10");
    assert_eq!(rows[0].display, "192.0.2.10");
    assert_eq!(rows[0].critical, 1);
    assert_eq!(rows[0].high, 1);
    assert_eq!(rows[0].medium, 0);
    assert_eq!(rows[0].low, 0);
    assert_eq!(rows[0].log, 0);
    assert!(!rows[0].is_total);

    assert_eq!(rows[1].key, "192.0.2.20");
    assert_eq!(rows[1].critical, 0);
    assert_eq!(rows[1].high, 0);
    assert_eq!(rows[1].medium, 1);
    assert_eq!(rows[1].low, 1);
    assert_eq!(rows[1].log, 1);
    assert!(!rows[1].is_total);

    assert_eq!(rows[2].key, "Total");
    assert_eq!(rows[2].display, "Total");
    assert_eq!(rows[2].critical, 1);
    assert_eq!(rows[2].high, 1);
    assert_eq!(rows[2].medium, 1);
    assert_eq!(rows[2].low, 1);
    assert_eq!(rows[2].log, 1);
    assert!(rows[2].is_total);
}

#[test]
fn build_overview_rows_returns_only_total_row_when_report_has_no_results() {
    let report = empty_report();
    let document = NativePdfDocument::new(&report);

    let rows = document.build_overview_rows();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "Total");
    assert_eq!(rows[0].critical, 0);
    assert_eq!(rows[0].high, 0);
    assert_eq!(rows[0].medium, 0);
    assert_eq!(rows[0].low, 0);
    assert_eq!(rows[0].log, 0);
    assert!(rows[0].is_total);
}

#[test]
fn build_overview_rows_groups_by_container_image_display_name() {
    let report = container_image_report();
    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::ContainerImage);

    let rows = document.build_overview_rows();

    assert_eq!(rows.len(), 2);

    assert_eq!(rows[0].key, "app:1.0");
    assert_eq!(rows[0].display, "app:1.0");
    assert_eq!(rows[0].critical, 1);
    assert_eq!(rows[0].low, 1);
    assert!(!rows[0].is_total);

    assert_eq!(rows[1].key, "Total");
    assert_eq!(rows[1].critical, 1);
    assert_eq!(rows[1].low, 1);
    assert!(rows[1].is_total);
}

#[test]
fn filter_keyword_value_returns_matching_keyword_value_case_insensitively() {
    let report = filtered_report();

    assert_eq!(
        filter_keyword_value(&report.report, "AUTOFP").as_deref(),
        Some("1")
    );
    assert_eq!(
        filter_keyword_value(&report.report, "apply_overrides").as_deref(),
        Some("1")
    );
    assert_eq!(
        filter_keyword_value(&report.report, "min_qod").as_deref(),
        Some("80")
    );
}

#[test]
fn filter_keyword_value_returns_none_for_missing_keyword() {
    let report = filtered_report();

    assert_eq!(filter_keyword_value(&report.report, "missing"), None);
}

#[test]
fn build_filter_summary_text_adds_messages_for_missing_levels() {
    let report = filtered_report();

    let text = build_filter_summary_text(&report.report, ReportTargetKind::Host);

    assert!(text.contains("Issues with the threat level \"Low\" are not shown."));
    assert!(text.contains("Issues with the threat level \"Log\" are not shown."));
    assert!(text.contains("Issues with the threat level \"Debug\" are not shown."));
    assert!(text.contains("Issues with the threat level \"False Positive\" are not shown."));
}

#[test]
fn build_filter_summary_text_does_not_add_missing_level_messages_for_empty_levels() {
    let report = parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <filters>
                    <keywords>
                        <keyword>
                            <column>levels</column>
                            <value>   </value>
                        </keyword>
                    </keywords>
                </filters>
                <results />
            </report>
        </report>
        "#,
    );

    let text = build_filter_summary_text(&report.report, ReportTargetKind::Host);

    assert!(!text.contains("Issues with the threat level"));
}

#[test]
fn result_count_summary_text_reports_zero_results() {
    let report = empty_report();

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains 0 results. Before filtering there were 0 results."
    );
}

#[test]
fn result_count_summary_text_reports_single_result_position() {
    let report = one_result_report();

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains result 4 of the 5 results selected by the filtering above. Before filtering there were 5 results."
    );
}

#[test]
fn result_count_summary_text_reports_result_range() {
    let report = filtered_report();

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains results 3 to 4 of the 6 results selected by the filtering described above. Before filtering there were 10 results."
    );
}

#[test]
fn result_count_summary_text_reports_all_filtered_results() {
    let report = overview_report();

    assert_eq!(
        result_count_summary_text(&report.report),
        "This report contains all 5 results selected by the filtering described above. Before filtering there were 8 results."
    );
}

#[test]
fn build_filter_summary_text_uses_default_filter_messages_without_filter_data() {
    let report = overview_report();

    let text = build_filter_summary_text(&report.report, ReportTargetKind::Host);

    assert!(text.contains("Vendor security updates are not trusted."));
    assert!(text.contains(
        "Overrides are off. Even when a result has an override, this report uses the actual threat of the result."
    ));
    assert!(text.contains("Information on overrides is included in the report."));
    assert!(text.contains("Notes are included in the report."));
    assert!(text.contains("Only results with a minimum QoD of 70 are shown."));
    assert!(
        text.contains(
            "This report contains all 5 results selected by the filtering described above."
        )
    );
}

#[test]
fn build_filter_summary_text_uses_filter_keyword_values() {
    let report = filtered_report();

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
}

#[test]
fn has_authentication_rows_is_false_for_non_host_target() {
    let report = container_image_report();
    let document = NativePdfDocument::new(&report);

    assert_eq!(document.target, ReportTargetKind::ContainerImage);
    assert!(!document.has_authentication_rows());
}

#[test]
fn write_authentication_table_returns_without_changing_page_for_report_without_auth_rows() {
    let report = overview_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_page_count = document.pdf.page_count();
    let initial_y = document.pdf.get_y();

    document.write_authentication_table("1.1");

    assert_eq!(document.pdf.page_count(), initial_page_count);
    assert_eq!(document.pdf.get_y().to_mm(), initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_result_overview_writes_pdf_content() {
    let report = overview_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_result_overview();

    assert!(document.pdf.page_count() >= 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_result_overview_handles_empty_results() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.write_result_overview();

    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}
