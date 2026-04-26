use gvmr_lite_rs::service::report_xml_builder::build_report_xml;
use serde_json::Value;

#[test]
fn builds_report_xml_matching_python_golden_file() {
    let input: Value = serde_json::from_str(include_str!("fixtures/report_input.json"))
        .expect("fixture JSON should be valid");

    let expected = include_str!("fixtures/report_expected.xml");

    let actual = build_report_xml(&input).expect("report XML should build");

    assert_eq!(
        normalize_xml(&actual),
        normalize_xml(expected),
        "generated report XML does not match Python golden output"
    );
}

fn normalize_xml(value: &str) -> String {
    value.replace("\r\n", "\n").trim().to_string()
}
