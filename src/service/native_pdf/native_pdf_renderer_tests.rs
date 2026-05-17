use std::collections::BTreeMap;

use quick_xml::de::from_str;

use super::*;
use crate::domain::report_model::ReportEnvelope;

fn parse_report(xml: &str) -> ReportEnvelope {
    from_str(xml).unwrap()
}

fn report_with_results(results_xml: &str) -> ReportEnvelope {
    parse_report(&format!(
        r#"
        <report id="outer-report" content_type="application/xml" extension="xml">
            <report id="inner-report">
                <scan_run_status>Done</scan_run_status>
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
        <report id="outer-report" content_type="application/xml" extension="xml">
            <report id="inner-report">
                <scan_run_status>Done</scan_run_status>
                <results>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn native_pdf_renderer_new_returns_renderer() {
    let renderer = NativePdfRenderer::new();

    let debug = format!("{renderer:?}");

    assert!(debug.contains("NativePdfRenderer"));
}

#[test]
fn native_pdf_renderer_default_returns_renderer() {
    let renderer = NativePdfRenderer;

    let debug = format!("{renderer:?}");

    assert!(debug.contains("NativePdfRenderer"));
}

#[test]
fn render_minimal_report_returns_pdf_bytes() {
    let report = minimal_report();
    let renderer = NativePdfRenderer::new();

    let bytes = renderer.render(&report).unwrap();

    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"%PDF"));
}

#[test]
fn render_report_with_findings_returns_pdf_bytes() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <severity>8.7</severity>
            <description>Test vulnerability description</description>
            <nvt oid="1.2.3.4">
                <name>Test NVT</name>
                <tags>summary=Summary text|impact=Impact text|solution=Solution text</tags>
            </nvt>
        </result>
        "#,
    );

    let renderer = NativePdfRenderer::new();

    let bytes = renderer.render(&report).unwrap();

    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"%PDF"));
}

#[test]
fn native_pdf_temp_path_uses_temp_dir_pid_prefix_and_pdf_extension() {
    let path = native_pdf_temp_path();

    let filename = path.file_name().unwrap().to_string_lossy();

    assert!(path.starts_with(std::env::temp_dir()));
    assert!(filename.starts_with(&format!("gvmr-lite-rs-native-pdf-{}-", std::process::id())));
    assert!(filename.ends_with(".pdf"));
}

#[test]
fn estimate_line_count_returns_zero_for_blank_text() {
    assert_eq!(estimate_line_count("", 80), 0);
    assert_eq!(estimate_line_count("   ", 80), 0);
    assert_eq!(estimate_line_count(" \n\t ", 80), 0);
}

#[test]
fn estimate_line_count_counts_single_line_using_current_estimation_formula() {
    assert_eq!(estimate_line_count("abc", 10), 1);
    assert_eq!(estimate_line_count("abcdefghij", 10), 2);
    assert_eq!(estimate_line_count("abcdefghijk", 10), 2);
}

#[test]
fn estimate_line_count_counts_multiple_lines() {
    assert_eq!(estimate_line_count("abc\ndef", 10), 2);
    assert_eq!(estimate_line_count("abc\n\ndef", 10), 3);
    assert_eq!(estimate_line_count("abcdefghijk\nabc", 10), 3);
}

#[test]
fn finding_key_orders_by_host_then_index() {
    let mut keys = vec![
        FindingKey {
            host: "host-b".to_string(),
            index: 0,
        },
        FindingKey {
            host: "host-a".to_string(),
            index: 2,
        },
        FindingKey {
            host: "host-a".to_string(),
            index: 1,
        },
    ];

    keys.sort();

    assert_eq!(
        keys,
        vec![
            FindingKey {
                host: "host-a".to_string(),
                index: 1,
            },
            FindingKey {
                host: "host-a".to_string(),
                index: 2,
            },
            FindingKey {
                host: "host-b".to_string(),
                index: 0,
            },
        ]
    );
}

#[test]
fn add_toc_entry_uses_zero_page_when_known_pages_are_missing() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    let link = renderer.pdf.add_link();

    renderer.add_toc_entry("1", "Result Overview", 1, link, None);

    assert_eq!(renderer.toc.len(), 1);
    assert_eq!(renderer.toc[0].number, "1");
    assert_eq!(renderer.toc[0].title, "Result Overview");
    assert_eq!(renderer.toc[0].level, 1);
    assert_eq!(renderer.toc[0].page, 0);
    assert_eq!(renderer.toc[0].link, link);
}

#[test]
fn add_toc_entry_uses_known_page_when_available() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    let link = renderer.pdf.add_link();

    let mut known_pages = BTreeMap::new();
    known_pages.insert("1".to_string(), 7);

    renderer.add_toc_entry("1", "Result Overview", 1, link, Some(&known_pages));

    assert_eq!(renderer.toc[0].page, 7);
}

#[test]
fn toc_pages_returns_number_to_page_mapping() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    let link_1 = renderer.pdf.add_link();
    let link_2 = renderer.pdf.add_link();

    renderer.add_toc_entry("1", "Result Overview", 1, link_1, None);
    renderer.add_toc_entry("2", "Results per Host", 1, link_2, None);
    renderer.set_toc_page("1", 3);
    renderer.set_toc_page("2", 4);

    let pages = renderer.toc_pages();

    assert_eq!(pages.get("1"), Some(&3));
    assert_eq!(pages.get("2"), Some(&4));
}

#[test]
fn set_toc_page_updates_matching_entry_only() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    let link_1 = renderer.pdf.add_link();
    let link_2 = renderer.pdf.add_link();

    renderer.add_toc_entry("1", "Result Overview", 1, link_1, None);
    renderer.add_toc_entry("2", "Results per Host", 1, link_2, None);

    renderer.set_toc_page("2", 9);
    renderer.set_toc_page("missing", 99);

    assert_eq!(renderer.toc[0].page, 0);
    assert_eq!(renderer.toc[1].page, 9);
}

#[test]
fn toc_link_returns_link_for_existing_entry() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    let link = renderer.pdf.add_link();

    renderer.add_toc_entry("1", "Result Overview", 1, link, None);

    assert_eq!(renderer.toc_link("1"), link);
}

#[test]
fn toc_link_returns_zero_for_missing_entry() {
    let report = minimal_report();
    let renderer = NativeTechnicalPdfRenderer::new(&report);

    assert_eq!(renderer.toc_link("missing"), 0);
}

#[test]
fn prepare_toc_creates_base_entries_for_empty_report() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.prepare_toc(None);

    assert_eq!(renderer.toc.len(), 2);

    assert_eq!(renderer.toc[0].number, "1");
    assert_eq!(renderer.toc[0].title, "Result Overview");
    assert_eq!(renderer.toc[0].level, 1);

    assert_eq!(renderer.toc[1].number, "2");
    assert_eq!(renderer.toc[1].title, "Results per Host");
    assert_eq!(renderer.toc[1].level, 1);
}

#[test]
fn prepare_toc_adds_hosts_and_findings_for_renderable_results() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-b</host>
            <port>443/tcp</port>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <port>22/tcp</port>
            <threat>Low</threat>
        </result>
        <result>
            <host>host-c</host>
            <port>80/tcp</port>
            <threat>Info</threat>
        </result>
        "#,
    );

    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.prepare_toc(None);

    let numbers = renderer
        .toc
        .iter()
        .map(|entry| entry.number.as_str())
        .collect::<Vec<_>>();

    assert_eq!(numbers, vec!["1", "2", "2.1", "2.1.1", "2.2", "2.2.1"]);

    assert!(renderer.host_links.contains_key("host-a"));
    assert!(renderer.host_links.contains_key("host-b"));
    assert!(!renderer.host_links.contains_key("host-c"));

    assert_eq!(renderer.finding_links.len(), 2);
}

#[test]
fn prepare_toc_uses_known_pages_for_second_pass() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
        </result>
        "#,
    );

    let mut known_pages = BTreeMap::new();
    known_pages.insert("1".to_string(), 2);
    known_pages.insert("2".to_string(), 3);
    known_pages.insert("2.1".to_string(), 4);
    known_pages.insert("2.1.1".to_string(), 5);

    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.prepare_toc(Some(&known_pages));

    let pages = renderer.toc_pages();

    assert_eq!(pages.get("1"), Some(&2));
    assert_eq!(pages.get("2"), Some(&3));
    assert_eq!(pages.get("2.1"), Some(&4));
    assert_eq!(pages.get("2.1.1"), Some(&5));
}

#[test]
fn group_results_by_host_groups_by_host_and_sorts_hosts() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-b</host>
            <port>443/tcp</port>
            <threat>High</threat>
        </result>
        <result>
            <host>host-a</host>
            <port>22/tcp</port>
            <threat>Low</threat>
        </result>
        <result>
            <host>host-b</host>
            <port>8443/tcp</port>
            <threat>Medium</threat>
        </result>
        "#,
    );

    let renderer = NativeTechnicalPdfRenderer::new(&report);

    let grouped = renderer.group_results_by_host();
    let hosts = grouped.keys().cloned().collect::<Vec<_>>();

    assert_eq!(hosts, vec!["host-a", "host-b"]);
    assert_eq!(grouped["host-a"].len(), 1);
    assert_eq!(grouped["host-b"].len(), 2);
}

#[test]
fn group_results_by_host_excludes_non_renderable_results() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
        </result>
        <result>
            <host>host-b</host>
            <port>80/tcp</port>
            <threat>Info</threat>
        </result>
        <result>
            <host>host-c</host>
            <port>80/tcp</port>
            <threat>Debug</threat>
        </result>
        <result>
            <host>host-d</host>
            <port>80/tcp</port>
            <threat>False Positive</threat>
        </result>
        "#,
    );

    let renderer = NativeTechnicalPdfRenderer::new(&report);

    let grouped = renderer.group_results_by_host();

    assert_eq!(grouped.len(), 1);
    assert!(grouped.contains_key("host-a"));
}

#[test]
fn group_results_by_host_limits_to_max_findings() {
    let mut results_xml = String::new();

    for index in 0..(MAX_FINDINGS + 10) {
        results_xml.push_str(&format!(
            r#"
            <result>
                <host>host-{index}</host>
                <port>443/tcp</port>
                <threat>High</threat>
            </result>
            "#
        ));
    }

    let report = report_with_results(&results_xml);
    let renderer = NativeTechnicalPdfRenderer::new(&report);

    let grouped = renderer.group_results_by_host();
    let total = grouped.values().map(Vec::len).sum::<usize>();

    assert_eq!(total, MAX_FINDINGS);
}

#[test]
fn build_overview_rows_counts_threats_per_host_and_total() {
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
        <result>
            <host>host-c</host>
            <threat>Info</threat>
        </result>
        "#,
    );

    let renderer = NativeTechnicalPdfRenderer::new(&report);

    let rows = renderer.build_overview_rows();

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
fn build_overview_rows_returns_total_zero_row_when_no_results_exist() {
    let report = minimal_report();
    let renderer = NativeTechnicalPdfRenderer::new(&report);

    let rows = renderer.build_overview_rows();

    assert_eq!(rows, vec![vec!["Total", "0", "0", "0", "0", "0"]]);
}

#[test]
fn write_cover_with_empty_toc_does_not_panic() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.write_cover();

    assert_eq!(renderer.pdf.page_no(), 1);
}

#[test]
fn write_result_overview_does_not_panic() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.prepare_toc(None);
    renderer.write_result_overview();

    assert!(renderer.pdf.page_no() >= 1);
}

#[test]
fn write_results_per_host_with_no_results_does_not_add_page() {
    let report = minimal_report();
    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.prepare_toc(None);

    let before = renderer.pdf.page_no();

    renderer.write_results_per_host();

    assert_eq!(renderer.pdf.page_no(), before);
}

#[test]
fn write_results_per_host_with_results_adds_page_and_sets_toc_pages() {
    let report = report_with_results(
        r#"
        <result>
            <host>host-a</host>
            <port>443/tcp</port>
            <threat>High</threat>
            <description>Description</description>
            <nvt>
                <name>NVT Name</name>
                <tags>summary=Summary text</tags>
            </nvt>
        </result>
        "#,
    );

    let mut renderer = NativeTechnicalPdfRenderer::new(&report);

    renderer.prepare_toc(None);
    renderer.write_results_per_host();

    assert!(renderer.pdf.page_no() >= 1);

    let pages = renderer.toc_pages();

    assert!(pages.get("2").copied().unwrap_or(0) > 0);
    assert!(pages.get("2.1").copied().unwrap_or(0) > 0);
    assert!(pages.get("2.1.1").copied().unwrap_or(0) > 0);
}
