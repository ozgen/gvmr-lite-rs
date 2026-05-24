use fpdf::{Pdf, Unit};

use crate::{
    domain::report_model::{ReportEnvelope, ReportResult},
    service::native_pdf::document::NativePdfDocument,
    xml::report_validator::parse_report_xml_flexible,
};

use super::{BoxFieldLine, box_field_lines, reference_url, split_long_word, wrap_single_line};

fn test_report() -> ReportEnvelope {
    parse_report_xml_flexible(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_start>2024-01-02T03:04:05Z</scan_start>
                <scan_end>2024-01-02T04:04:05Z</scan_end>
                <scan_run_status>Done</scan_run_status>
                <task>
                    <name>Test Task</name>
                </task>
                <host>
                    <ip>192.0.2.10</ip>
                </host>
                <result_count>
                    <full>1</full>
                    <filtered>1</filtered>
                </result_count>
                <results>
                    <result id="result-1">
                        <name>Test Finding</name>
                        <description>Finding description</description>
                        <threat>Medium</threat>
                        <severity>5.0</severity>
                        <qod>
                            <value>80</value>
                        </qod>
                        <nvt oid="1.2.3.4">
                            <name>Test NVT</name>
                            <tags>summary=Summary text|impact=Impact text|solution=Solution text|affected=Affected software|insight=Insight text|vuldetect=Detection text</tags>
                            <refs>
                                <ref type="url" id="https://example.test/advisory" />
                            </refs>
                        </nvt>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
    .expect("test report XML should parse")
}

fn test_result(report: &ReportEnvelope) -> &ReportResult {
    &report
        .report
        .results
        .as_ref()
        .expect("test report should have results")
        .result[0]
}

#[test]
fn wrap_single_line_wraps_on_word_boundary() {
    let lines = wrap_single_line("alpha beta gamma", 10);

    assert_eq!(lines, vec!["alpha beta", "gamma"]);
}

#[test]
fn wrap_single_line_splits_long_word() {
    let lines = wrap_single_line("abcdefghijkl", 5);

    assert_eq!(lines, vec!["abcde", "fghij", "kl"]);
}

#[test]
fn split_long_word_splits_by_character_count() {
    let chunks = split_long_word("abcdefghijkl", 4);

    assert_eq!(chunks, vec!["abcd", "efgh", "ijkl"]);
}

#[test]
fn split_long_word_handles_unicode_characters() {
    let chunks = split_long_word("äöüßabc", 3);

    assert_eq!(chunks, vec!["äöü", "ßab", "c"]);
}

#[test]
fn reference_url_detects_uppercase_url_prefix() {
    assert_eq!(
        reference_url("URL: https://example.test/advisory"),
        Some("https://example.test/advisory")
    );
}

#[test]
fn reference_url_detects_lowercase_url_prefix() {
    assert_eq!(
        reference_url("url: https://example.test/advisory"),
        Some("https://example.test/advisory")
    );
}

#[test]
fn reference_url_detects_http_url() {
    assert_eq!(
        reference_url("http://example.test/advisory"),
        Some("http://example.test/advisory")
    );
}

#[test]
fn reference_url_detects_https_url() {
    assert_eq!(
        reference_url("https://example.test/advisory"),
        Some("https://example.test/advisory")
    );
}

#[test]
fn reference_url_returns_none_for_plain_reference_text() {
    assert_eq!(reference_url("CVE-2024-0001"), None);
}

#[test]
fn write_box_field_ignores_none_value() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_box_field("Summary", None);

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.get_y().to_mm(), initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_box_field_ignores_empty_value() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_box_field("Summary", Some("   ".to_string()));

    assert_eq!(document.pdf.page_count(), 1);
    assert_eq!(document.pdf.get_y().to_mm(), initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_box_field_writes_non_empty_value() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let initial_y = document.pdf.get_y();

    document.write_box_field("Summary", Some("A useful summary".to_string()));

    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert!(document.pdf.ok());
}

#[test]
fn write_box_field_writes_references_field() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();

    document.write_box_field(
        "References",
        Some("url: https://example.test/advisory".to_string()),
    );

    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_box_field_paginates_long_value() {
    let report = test_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();

    let long_value = "very long finding text ".repeat(800);

    document.write_box_field("Summary", Some(long_value));

    assert!(document.pdf.page_count() > 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_finding_card_writes_result_without_breaking_pdf_state() {
    let report = test_report();
    let result = test_result(&report);
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();

    document.write_finding_card("Test Finding", result);

    assert!(document.pdf.page_count() >= 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_finding_card_adds_page_when_current_page_has_no_space() {
    let report = test_report();
    let result = test_result(&report);
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(Unit::mm(285.0));

    document.write_finding_card("Test Finding", result);

    assert!(document.pdf.page_count() >= 2);
    assert!(document.pdf.ok());
}

#[test]
fn reference_url_strips_lowercase_url_prefix() {
    assert_eq!(
        reference_url("url: https://redis.io/blog/security-advisory-cve-2025-49844/"),
        Some("https://redis.io/blog/security-advisory-cve-2025-49844/")
    );
}

#[test]
fn reference_url_strips_uppercase_url_prefix() {
    assert_eq!(
        reference_url("URL: https://redis.io/blog/security-advisory-cve-2025-49844/"),
        Some("https://redis.io/blog/security-advisory-cve-2025-49844/")
    );
}

#[test]
fn reference_url_trims_before_checking_url() {
    assert_eq!(
        reference_url("   url: https://example.test/advisory   "),
        Some("https://example.test/advisory")
    );
}

#[test]
fn box_field_lines_returns_text_lines_for_non_reference_field() {
    let lines = box_field_lines("Summary", "url: https://example.test/advisory", 95);

    assert_eq!(
        lines,
        vec![BoxFieldLine::Text(
            "url: https://example.test/advisory".to_string()
        )]
    );
}

#[test]
fn box_field_lines_strips_url_prefix_for_reference_field() {
    let lines = box_field_lines(
        "References",
        "url: https://redis.io/blog/security-advisory-cve-2025-49844/",
        95,
    );

    assert_eq!(
        lines,
        vec![BoxFieldLine::Url {
            text: "https://redis.io/blog/security-advisory-cve-2025-49844/".to_string(),
            target: "https://redis.io/blog/security-advisory-cve-2025-49844/".to_string(),
        }]
    );
}

#[test]
fn box_field_lines_marks_all_wrapped_reference_url_chunks_as_url() {
    let url = "https://redrays.io/blog/poc-for-cve-2025-49844-cve-2025-46817-and-cve-2025-46818-critical-lua-engine-vulnerabilities/";
    let value = format!("url: {url}");

    let lines = box_field_lines("References", &value, 40);

    assert!(lines.len() > 1);

    for line in lines {
        match line {
            BoxFieldLine::Url { text, target } => {
                assert!(!text.starts_with("url:"));
                assert_eq!(target, url);
            }
            BoxFieldLine::Text(text) => {
                panic!("expected URL line, got text line {text:?}");
            }
        }
    }
}

#[test]
fn box_field_lines_keeps_plain_reference_text_black() {
    let lines = box_field_lines("References", "cve: CVE-2025-49844", 95);

    assert_eq!(
        lines,
        vec![BoxFieldLine::Text("cve: CVE-2025-49844".to_string())]
    );
}

#[test]
fn box_field_lines_handles_mixed_reference_values() {
    let lines = box_field_lines(
        "References",
        "cve: CVE-2025-49844\nurl: https://redis.io/blog/security-advisory-cve-2025-49844/",
        95,
    );

    assert_eq!(
        lines,
        vec![
            BoxFieldLine::Text("cve: CVE-2025-49844".to_string()),
            BoxFieldLine::Url {
                text: "https://redis.io/blog/security-advisory-cve-2025-49844/".to_string(),
                target: "https://redis.io/blog/security-advisory-cve-2025-49844/".to_string(),
            },
        ]
    );
}

#[test]
fn box_field_lines_preserves_empty_lines() {
    let lines = box_field_lines(
        "References",
        "cve: CVE-2025-49844\n\nurl: https://example.test",
        95,
    );

    assert_eq!(
        lines,
        vec![
            BoxFieldLine::Text("cve: CVE-2025-49844".to_string()),
            BoxFieldLine::Text(String::new()),
            BoxFieldLine::Url {
                text: "https://example.test".to_string(),
                target: "https://example.test".to_string(),
            },
        ]
    );
}
