use super::{ReportXmlValidationError, validate_report_xml};

#[test]
fn accepts_report_root() {
    let xml = r#"<report id="123"></report>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn accepts_self_closing_report_root() {
    let xml = r#"<report id="123"/>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn accepts_xml_declaration_before_report_root() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?><report></report>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn accepts_comment_before_report_root() {
    let xml = r#"<!-- generated report --><report></report>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Ok(()));
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
