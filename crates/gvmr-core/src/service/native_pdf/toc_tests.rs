use std::collections::BTreeMap;

use fpdf::Pdf;

use crate::{
    domain::report_model::ReportEnvelope,
    service::native_pdf::{document::NativePdfDocument, grouping::FindingKey},
    xml::report_validator::parse_report_xml_flexible,
};

use super::{TocEntry, estimated_text_width_mm, shorten_toc_title_for_width, toc_leader_dots};

fn parse_report(xml: &str) -> ReportEnvelope {
    parse_report_xml_flexible(xml).expect("test report XML should parse")
}

fn host_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <result_count>
                    <full>2</full>
                    <filtered>2</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <port>80/tcp</port>
                        <name>High Finding</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <port>443/tcp</port>
                        <name>Medium Finding</name>
                        <threat>Medium</threat>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn multi_host_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <result_count>
                    <full>3</full>
                    <filtered>3</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>192.0.2.20</host>
                        <port>80/tcp</port>
                        <name>Finding B</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <port>443/tcp</port>
                        <name>Finding A</name>
                        <threat>Medium</threat>
                    </result>
                    <result id="result-3">
                        <host>192.0.2.20</host>
                        <port>22/tcp</port>
                        <name>Finding C</name>
                        <threat>Low</threat>
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

                <result_count>
                    <full>2</full>
                    <filtered>2</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Agent High</name>
                        <threat>High</threat>
                    </result>
                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <name>Agent Low</name>
                        <threat>Low</threat>
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

                <result_count>
                    <full>2</full>
                    <filtered>2</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>sha256:first-digest</host>
                        <name>Image Critical</name>
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
                        <name>Image Low</name>
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

fn toc_entry(number: &str, title: &str, level: usize, page: usize, link: usize) -> TocEntry {
    TocEntry {
        number: number.to_string(),
        title: title.to_string(),
        level,
        page,
        link,
    }
}

#[test]
fn toc_entry_is_cloneable_and_debuggable() {
    let entry = toc_entry("1", "Result Overview", 1, 2, 3);
    let cloned = entry.clone();

    assert_eq!(cloned.number, "1");
    assert_eq!(cloned.title, "Result Overview");
    assert_eq!(cloned.level, 1);
    assert_eq!(cloned.page, 2);
    assert_eq!(cloned.link, 3);
    assert!(format!("{entry:?}").contains("Result Overview"));
}

#[test]
fn add_toc_entry_without_known_pages_sets_page_to_zero() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.add_toc_entry("1", "Result Overview", 1, 42, None);

    assert_eq!(document.toc.len(), 1);
    assert_eq!(document.toc[0].number, "1");
    assert_eq!(document.toc[0].title, "Result Overview");
    assert_eq!(document.toc[0].level, 1);
    assert_eq!(document.toc[0].page, 0);
    assert_eq!(document.toc[0].link, 42);
}

#[test]
fn add_toc_entry_uses_known_page_when_available() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    let mut known_pages = BTreeMap::new();
    known_pages.insert("1".to_string(), 7);

    document.add_toc_entry("1", "Result Overview", 1, 42, Some(&known_pages));

    assert_eq!(document.toc[0].page, 7);
}

#[test]
fn add_toc_entry_uses_zero_when_known_page_is_missing() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    let known_pages = BTreeMap::new();

    document.add_toc_entry("1", "Result Overview", 1, 42, Some(&known_pages));

    assert_eq!(document.toc[0].page, 0);
}

#[test]
fn toc_pages_returns_number_to_page_map() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![
        toc_entry("1", "Result Overview", 1, 2, 10),
        toc_entry("2", "Results per Host", 1, 5, 11),
    ];

    let pages = document.toc_pages();

    assert_eq!(pages.len(), 2);
    assert_eq!(pages["1"], 2);
    assert_eq!(pages["2"], 5);
}

#[test]
fn set_toc_page_updates_matching_entry() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![
        toc_entry("1", "Result Overview", 1, 0, 10),
        toc_entry("2", "Results per Host", 1, 0, 11),
    ];

    document.set_toc_page("2", 9);

    assert_eq!(document.toc[0].page, 0);
    assert_eq!(document.toc[1].page, 9);
}

#[test]
fn set_toc_page_ignores_missing_entry() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![toc_entry("1", "Result Overview", 1, 0, 10)];

    document.set_toc_page("missing", 9);

    assert_eq!(document.toc[0].page, 0);
}

#[test]
fn toc_link_returns_matching_link() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![
        toc_entry("1", "Result Overview", 1, 0, 10),
        toc_entry("2", "Results per Host", 1, 0, 11),
    ];

    assert_eq!(document.toc_link("2"), 11);
}

#[test]
fn toc_link_returns_zero_for_missing_entry() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![toc_entry("1", "Result Overview", 1, 0, 10)];

    assert_eq!(document.toc_link("missing"), 0);
}

#[test]
fn prepare_toc_clears_previous_entries_and_links() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);

    document.toc = vec![toc_entry("old", "Old", 1, 1, 99)];
    document.host_links.insert("old-host".to_string(), 99);
    document.finding_links.insert(
        FindingKey {
            host: "old-host".to_string(),
            index: 0,
        },
        99,
    );

    document.prepare_toc(None);

    assert!(!document.toc.iter().any(|entry| entry.number == "old"));
    assert!(!document.host_links.contains_key("old-host"));
    assert!(!document.finding_links.contains_key(&FindingKey {
        host: "old-host".to_string(),
        index: 0,
    }));
}

#[test]
fn prepare_toc_for_empty_report_adds_overview_and_results_entries() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.prepare_toc(None);

    let numbers = document
        .toc
        .iter()
        .map(|entry| entry.number.as_str())
        .collect::<Vec<_>>();

    assert_eq!(numbers, vec!["1", "2"]);
    assert_eq!(document.toc[0].title, "Result Overview");
    assert_eq!(document.toc[1].title, "Results per Host");
    assert!(document.host_links.is_empty());
    assert!(document.finding_links.is_empty());
}

#[test]
fn prepare_toc_for_host_report_adds_host_and_finding_entries() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);

    document.prepare_toc(None);

    let numbers = document
        .toc
        .iter()
        .map(|entry| entry.number.as_str())
        .collect::<Vec<_>>();

    assert_eq!(numbers, vec!["1", "2", "2.1", "2.1.1", "2.1.2"]);

    assert_eq!(document.toc[2].title, "192.0.2.10");
    assert_eq!(document.toc[3].title, "High 80/tcp");
    assert_eq!(document.toc[4].title, "Medium 443/tcp");

    assert!(document.host_links.contains_key("192.0.2.10"));
    assert!(document.finding_links.contains_key(&FindingKey {
        host: "192.0.2.10".to_string(),
        index: 0,
    }));
    assert!(document.finding_links.contains_key(&FindingKey {
        host: "192.0.2.10".to_string(),
        index: 1,
    }));
}

#[test]
fn prepare_toc_for_multi_host_report_numbers_hosts_in_sorted_order() {
    let report = multi_host_report();
    let mut document = NativePdfDocument::new(&report);

    document.prepare_toc(None);

    let host_entries = document
        .toc
        .iter()
        .filter(|entry| entry.level == 2)
        .map(|entry| (entry.number.as_str(), entry.title.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(
        host_entries,
        vec![("2.1", "192.0.2.10"), ("2.2", "192.0.2.20")]
    );
}

#[test]
fn prepare_toc_for_agent_report_groups_findings_by_threat() {
    let report = agent_report();
    let mut document = NativePdfDocument::new(&report);

    document.prepare_toc(None);

    let numbers = document
        .toc
        .iter()
        .map(|entry| entry.number.as_str())
        .collect::<Vec<_>>();

    assert_eq!(numbers, vec!["1", "2", "2.1", "2.1.1", "2.1.2"]);

    assert_eq!(document.toc[1].title, "Results per Agent");
    assert_eq!(document.toc[2].title, "agent-a");
    assert_eq!(document.toc[3].title, "High");
    assert_eq!(document.toc[4].title, "Low");
}

#[test]
fn prepare_toc_for_container_image_report_groups_findings_by_threat() {
    let report = container_image_report();
    let mut document = NativePdfDocument::new(&report);

    document.prepare_toc(None);

    let numbers = document
        .toc
        .iter()
        .map(|entry| entry.number.as_str())
        .collect::<Vec<_>>();

    assert_eq!(numbers, vec!["1", "2", "2.1", "2.1.1", "2.1.2"]);

    assert_eq!(document.toc[1].title, "Results per Image");
    assert_eq!(document.toc[2].title, "app:1.0");
    assert_eq!(document.toc[3].title, "Critical");
    assert_eq!(document.toc[4].title, "Low");
}

#[test]
fn prepare_toc_uses_known_pages() {
    let report = host_report();
    let mut document = NativePdfDocument::new(&report);

    let mut known_pages = BTreeMap::new();
    known_pages.insert("1".to_string(), 2);
    known_pages.insert("2".to_string(), 5);
    known_pages.insert("2.1".to_string(), 6);
    known_pages.insert("2.1.1".to_string(), 7);

    document.prepare_toc(Some(&known_pages));

    assert_eq!(document.toc_pages()["1"], 2);
    assert_eq!(document.toc_pages()["2"], 5);
    assert_eq!(document.toc_pages()["2.1"], 6);
    assert_eq!(document.toc_pages()["2.1.1"], 7);
    assert_eq!(document.toc_pages()["2.1.2"], 0);
}

#[test]
fn write_toc_entry_advances_y() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let link = document.pdf.add_link();
    let entry = toc_entry("1", "Result Overview", 1, 3, link);
    let initial_y = document.pdf.get_y();

    document.write_toc_entry(&entry);

    assert!(document.pdf.get_y().to_mm() > initial_y.to_mm());
    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn write_toc_entry_adds_page_when_no_space_remains() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    document.pdf.set_y(fpdf::Unit::mm(285.0));

    let link = document.pdf.add_link();
    let entry = toc_entry("1", "Result Overview", 1, 3, link);

    document.write_toc_entry(&entry);

    assert!(document.pdf.page_count() >= 2);
    assert!(document.pdf.ok());
}

#[test]
fn write_toc_entry_handles_long_and_dirty_title() {
    let report = empty_report();
    let mut document = NativePdfDocument::new(&report);

    document.pdf.add_page();
    let link = document.pdf.add_link();

    let entry = toc_entry(
        "2.1.1",
        "  Very long title\nwith weird spacing and enough text to require shortening in the TOC row  ",
        3,
        42,
        link,
    );

    document.write_toc_entry(&entry);

    assert_eq!(document.pdf.page_count(), 1);
    assert!(document.pdf.ok());
}

#[test]
fn toc_leader_dots_returns_100_dots() {
    let dots = toc_leader_dots();

    assert_eq!(dots.len(), 100);
    assert!(dots.chars().all(|ch| ch == '.'));
}

#[test]
fn estimated_text_width_mm_returns_zero_for_empty_text() {
    assert_eq!(estimated_text_width_mm("", 8.5), 0.0);
}

#[test]
fn estimated_text_width_mm_increases_with_text_length() {
    let short = estimated_text_width_mm("abc", 8.5);
    let long = estimated_text_width_mm("abcdef", 8.5);

    assert!(long > short);
}

#[test]
fn estimated_text_width_mm_increases_with_font_size() {
    let small = estimated_text_width_mm("abc", 8.5);
    let large = estimated_text_width_mm("abc", 14.0);

    assert!(large > small);
}

#[test]
fn shorten_toc_title_for_width_returns_original_when_it_fits() {
    let value = shorten_toc_title_for_width("Short title", 80.0, 8.5);

    assert_eq!(value, "Short title");
}

#[test]
fn shorten_toc_title_for_width_shortens_long_value() {
    let value = shorten_toc_title_for_width(
        "This is a very long title that should be shortened",
        20.0,
        8.5,
    );

    assert!(value.ends_with('…'));
    assert!(value.len() < "This is a very long title that should be shortened".len());
}

#[test]
fn shorten_toc_title_for_width_returns_ellipsis_when_nothing_fits() {
    let value = shorten_toc_title_for_width("Long", 0.1, 8.5);

    assert_eq!(value, "…");
}
