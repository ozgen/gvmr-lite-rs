use super::{ReportXmlValidationError, parse_report_xml, validate_report_xml};

#[test]
fn validate_accepts_valid_report_envelope() {
    let xml = valid_report_xml();

    let result = validate_report_xml(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn parse_accepts_valid_report_envelope_and_returns_model() {
    let xml = valid_report_xml();

    let envelope = parse_report_xml(xml).unwrap();

    assert_eq!(envelope.report.id.as_deref(), Some("inner-report"));
}

#[test]
fn validate_accepts_valid_report_envelope_with_xml_declaration() {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>{}"#,
        valid_report_xml()
    );

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn parse_accepts_valid_report_envelope_with_xml_declaration() {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>{}"#,
        valid_report_xml()
    );

    let envelope = parse_report_xml(&xml).unwrap();

    assert_eq!(envelope.report.id.as_deref(), Some("inner-report"));
}

#[test]
fn validate_accepts_valid_report_envelope_with_comment_before_root() {
    let xml = format!(r#"<!-- generated report -->{}"#, valid_report_xml());

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn validate_accepts_valid_report_envelope_with_processing_instruction_before_root() {
    let xml = format!(
        r#"<?xml-stylesheet type="text/xsl" href="report.xsl"?>{}"#,
        valid_report_xml()
    );

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn validate_accepts_valid_report_envelope_with_doctype_before_root() {
    let xml = format!(r#"<!DOCTYPE report>{}"#, valid_report_xml());

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn validate_accepts_whitespace_before_root_element() {
    let xml = format!("\n\t  {}", valid_report_xml());

    let result = validate_report_xml(&xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn validate_accepts_comment_after_root_element() {
    let xml = format!("{}<!-- end -->", valid_report_xml());

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
fn validate_rejects_wrong_root_element() {
    let xml = r#"<foo></foo>"#;

    let result = validate_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::InvalidRootElement));
}

#[test]
fn parse_rejects_wrong_root_element() {
    let xml = r#"<foo></foo>"#;

    let result = parse_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::InvalidRootElement));
}

#[test]
fn rejects_self_closing_wrong_root_element() {
    let xml = r#"<foo/>"#;

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
fn rejects_non_whitespace_text_before_root_after_xml_declaration() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>hello<report></report>"#;

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
fn rejects_whitespace_only_document() {
    let xml = " \n\t  ";

    let result = validate_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::EmptyDocument));
}

#[test]
fn parse_rejects_empty_document() {
    let xml = "";

    let result = parse_report_xml(xml);

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
fn rejects_mismatched_closing_tag() {
    let xml = r#"<report></foo>"#;

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

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string()
        ))
    );
}

#[test]
fn parse_rejects_valid_root_with_missing_inner_report_id() {
    let xml = r#"
        <report id="outer-report">
            <report>
                <scan_run_status>Done</scan_run_status>
            </report>
        </report>
    "#;

    let result = parse_report_xml(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string()
        ))
    );
}

#[test]
fn rejects_valid_root_with_blank_inner_report_id() {
    let xml = r#"
        <report id="outer-report">
            <report id="   ">
                <scan_run_status>Done</scan_run_status>
            </report>
        </report>
    "#;

    let result = validate_report_xml(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string()
        ))
    );
}

#[test]
fn rejects_invalid_xml_attribute_syntax() {
    let xml = r#"<report id="outer-report><report id="inner-report"></report></report>"#;

    let result = validate_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidXml(_))
    ));
}

#[test]
fn rejects_xml_with_multiple_root_elements() {
    let xml = r#"
        <report id="outer-report">
            <report id="inner-report">
                <scan_run_status>Done</scan_run_status>
            </report>
        </report>
        <report id="second-root">
            <report id="inner-report-2" />
        </report>
    "#;

    let result = validate_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidXml(_))
            | Err(ReportXmlValidationError::InvalidStructure(_))
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
