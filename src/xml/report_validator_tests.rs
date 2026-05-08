use super::{ReportXmlValidationError, validate_report_xml};

#[test]
fn accepts_valid_report_envelope() {
    let xml = valid_report_xml();

    let result = validate_report_xml(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn accepts_valid_report_envelope_with_xml_declaration() {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>{}"#,
        valid_report_xml()
    );

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn accepts_valid_report_envelope_with_comment_before_root() {
    let xml = format!(r#"<!-- generated report -->{}"#, valid_report_xml());

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn rejects_report_root_without_inner_report() {
    let xml = r#"<report id="123"></report>"#;

    let result = validate_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(_))
            | Err(ReportXmlValidationError::InvalidXml(_))
    ));
}

#[test]
fn rejects_self_closing_report_root_without_inner_report() {
    let xml = r#"<report id="123"/>"#;

    let result = validate_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(_))
            | Err(ReportXmlValidationError::InvalidXml(_))
    ));
}

#[test]
fn rejects_wrong_root_element() {
    let xml = r#"<foo></foo>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::InvalidRootElement));
}

#[test]
fn rejects_text_before_root_element() {
    let xml = r#"hello<report></report>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::TextBeforeRootElement));
}

#[test]
fn rejects_empty_document() {
    let xml = "";

    let result = validate_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::EmptyDocument));
}

#[test]
fn rejects_unclosed_report_element() {
    let xml = "<report>";

    let result = validate_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidXml(_))
    ));
}

#[test]
fn rejects_plain_text() {
    let xml = "not xml";

    let result = validate_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::TextBeforeRootElement));
}

#[test]
fn rejects_valid_root_with_missing_inner_report_id() {
    let xml = r#"
        <report id="outer-report">
            <report>
                <scan_run_status>Done</scan_run_status>
            </report>
        </report>
    "#;

    let result = validate_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(_))
    ));
}

fn valid_report_xml() -> &'static str {
    r#"
        <report id="outer-report" content_type="application/xml" extension="xml">
            <report id="inner-report">
                <scan_run_status>Done</scan_run_status>
                <results>
                </results>
            </report>
        </report>
    "#
}
