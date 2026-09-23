use crate::{
    domain::report_model::{DeltaState, ResultDelta},
    xml::report_validator::{
        parse_inner_report_xml, parse_report_xml_flexible, validate_report_xml_flexible,
    },
};

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

#[test]
fn validate_flexible_accepts_valid_report_envelope() {
    let xml = valid_report_xml();

    let result = validate_report_xml_flexible(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn parse_flexible_accepts_valid_report_envelope_and_returns_model() {
    let xml = valid_report_xml();

    let envelope = parse_report_xml_flexible(xml).unwrap();

    assert_eq!(envelope.report.id.as_deref(), Some("inner-report"));
}

#[test]
fn parse_inner_report_accepts_valid_report_envelope_and_returns_inner_report() {
    let xml = valid_report_xml();

    let inner = parse_inner_report_xml(xml).unwrap();

    assert_eq!(inner.id.as_deref(), Some("inner-report"));
}

#[test]
fn validate_flexible_accepts_valid_inner_report_directly() {
    let xml = valid_inner_report_xml();

    let result = validate_report_xml_flexible(xml);

    assert_eq!(result, Ok(()));
}

#[test]
fn parse_flexible_accepts_valid_inner_report_directly_and_wraps_it_in_envelope() {
    let xml = valid_inner_report_xml();

    let envelope = parse_report_xml_flexible(xml).unwrap();

    assert_eq!(envelope.report.id.as_deref(), Some("inner-report"));
}

#[test]
fn parse_inner_report_accepts_valid_inner_report_directly() {
    let xml = valid_inner_report_xml();

    let inner = parse_inner_report_xml(xml).unwrap();

    assert_eq!(inner.id.as_deref(), Some("inner-report"));
}

#[test]
fn parse_audit_report_parses_report_compliance_summary() {
    let report =
        parse_inner_report_xml(valid_audit_report_xml()).expect("audit report should parse");

    let count = report
        .compliance_count
        .as_ref()
        .expect("compliance count should exist");

    assert_eq!(count.full.as_deref(), Some("184"));
    assert_eq!(count.filtered.as_deref(), Some("183"));

    assert_eq!(
        count
            .yes
            .as_ref()
            .and_then(|value| value.filtered.as_deref()),
        Some("5")
    );

    assert_eq!(
        count
            .no
            .as_ref()
            .and_then(|value| value.filtered.as_deref()),
        Some("1")
    );

    assert_eq!(
        count
            .incomplete
            .as_ref()
            .and_then(|value| value.filtered.as_deref()),
        Some("146")
    );

    assert_eq!(
        count
            .undefined
            .as_ref()
            .and_then(|value| value.filtered.as_deref()),
        Some("31")
    );

    let compliance = report
        .compliance
        .as_ref()
        .expect("compliance summary should exist");

    assert_eq!(compliance.full.as_deref(), Some("no"));
    assert_eq!(compliance.filtered.as_deref(), Some("no"));
}

#[test]
fn parse_audit_report_parses_host_compliance() {
    let report =
        parse_inner_report_xml(valid_audit_report_xml()).expect("audit report should parse");

    let host = report.hosts_detail.first().expect("host should exist");

    assert_eq!(host.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(host.host_compliance.as_deref(), Some("no"));

    let count = host
        .compliance_count
        .as_ref()
        .expect("host compliance count should exist");

    assert_eq!(count.page.as_deref(), Some("183"));

    assert_eq!(
        count.yes.as_ref().and_then(|value| value.page.as_deref()),
        Some("5")
    );

    assert_eq!(
        count.no.as_ref().and_then(|value| value.page.as_deref()),
        Some("1")
    );

    assert_eq!(
        count
            .incomplete
            .as_ref()
            .and_then(|value| value.page.as_deref()),
        Some("146")
    );

    assert_eq!(
        count
            .undefined
            .as_ref()
            .and_then(|value| value.page.as_deref()),
        Some("31")
    );
}

#[test]
fn parse_audit_report_parses_result_compliance() {
    let report =
        parse_inner_report_xml(valid_audit_report_xml()).expect("audit report should parse");

    let result = report
        .results
        .as_ref()
        .and_then(|results| results.result.first())
        .expect("result should exist");

    assert_eq!(result.compliance.as_deref(), Some("yes"));
}

#[test]
fn strict_validate_still_rejects_valid_inner_report_directly() {
    let xml = valid_inner_report_xml();

    let result = validate_report_xml(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "expected report envelope with nested inner report".to_string()
        ))
    );
}

#[test]
fn strict_parse_still_rejects_valid_inner_report_directly() {
    let xml = valid_inner_report_xml();

    let result = parse_report_xml(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "expected report envelope with nested inner report".to_string()
        ))
    );
}

#[test]
fn validate_flexible_rejects_inner_report_with_missing_id() {
    let xml = r#"
        <report>
            <scan_run_status>Done</scan_run_status>
        </report>
    "#;

    let result = validate_report_xml_flexible(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string()
        ))
    );
}

#[test]
fn parse_flexible_rejects_inner_report_with_missing_id() {
    let xml = r#"
        <report>
            <scan_run_status>Done</scan_run_status>
        </report>
    "#;

    let result = parse_report_xml_flexible(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string()
        ))
    );
}

#[test]
fn parse_inner_report_rejects_inner_report_with_missing_id() {
    let xml = r#"
        <report>
            <scan_run_status>Done</scan_run_status>
        </report>
    "#;

    let result = parse_inner_report_xml(xml);

    assert_eq!(
        result,
        Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string()
        ))
    );
}

#[test]
fn validate_flexible_rejects_wrong_root_element() {
    let xml = r#"<foo></foo>"#;

    let result = validate_report_xml_flexible(xml);

    assert_eq!(result, Err(ReportXmlValidationError::InvalidRootElement));
}

#[test]
fn parse_flexible_rejects_wrong_root_element() {
    let xml = r#"<foo></foo>"#;

    let result = parse_report_xml_flexible(xml);

    assert_eq!(result, Err(ReportXmlValidationError::InvalidRootElement));
}

#[test]
fn parse_inner_report_rejects_wrong_root_element() {
    let xml = r#"<foo></foo>"#;

    let result = parse_inner_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::InvalidRootElement));
}

#[test]
fn validate_flexible_rejects_empty_document() {
    let xml = "";

    let result = validate_report_xml_flexible(xml);

    assert_eq!(result, Err(ReportXmlValidationError::EmptyDocument));
}

#[test]
fn parse_flexible_rejects_empty_document() {
    let xml = "";

    let result = parse_report_xml_flexible(xml);

    assert_eq!(result, Err(ReportXmlValidationError::EmptyDocument));
}

#[test]
fn parse_inner_report_rejects_empty_document() {
    let xml = "";

    let result = parse_inner_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::EmptyDocument));
}

#[test]
fn parse_inner_report_rejects_text_before_root_element() {
    let xml = r#"hello<report id="inner-report"></report>"#;

    let result = parse_inner_report_xml(xml);

    assert_eq!(result, Err(ReportXmlValidationError::TextBeforeRootElement));
}

#[test]
fn parse_inner_report_rejects_xml_with_multiple_root_elements() {
    let xml = r#"
        <report id="inner-report">
            <scan_run_status>Done</scan_run_status>
        </report>
        <report id="second-root">
            <scan_run_status>Done</scan_run_status>
        </report>
    "#;

    let result = parse_inner_report_xml(xml);

    assert!(matches!(
        result,
        Err(ReportXmlValidationError::InvalidXml(_))
            | Err(ReportXmlValidationError::InvalidStructure(_))
    ));
}

// -----------------------------------------------------------------------------
// Delta report tests
// -----------------------------------------------------------------------------

#[test]
fn parse_inner_delta_report_parses_report_metadata() {
    let report =
        parse_inner_report_xml(valid_inner_delta_report_xml()).expect("delta report should parse");

    assert_eq!(report.id.as_deref(), Some("current-report"));
    assert_eq!(report.report_type.as_deref(), Some("delta"));
    assert!(report.is_delta_report());

    let delta = report.delta.as_ref().expect("report delta should exist");
    let baseline = delta.report.as_ref().expect("baseline report should exist");

    assert_eq!(baseline.id.as_deref(), Some("baseline-report"));
    assert_eq!(baseline.scan_run_status.as_deref(), Some("Done"));
    assert_eq!(baseline.timestamp.as_deref(), Some("2026-05-29T08:40:02Z"));
    assert_eq!(baseline.scan_start.as_deref(), Some("2026-05-29T08:40:23Z"));
    assert_eq!(baseline.scan_end.as_deref(), Some("2026-05-29T08:51:04Z"));
}

#[test]
fn parse_inner_delta_report_parses_changed_result() {
    let report =
        parse_inner_report_xml(valid_inner_delta_report_xml()).expect("delta report should parse");

    let results = report.results.as_ref().expect("results should exist");

    let result = results
        .result
        .iter()
        .find(|result| result.id.as_deref() == Some("changed-result"))
        .expect("changed result should exist");

    assert_eq!(result.compliance.as_deref(), Some("incomplete"));

    let delta = result
        .delta
        .as_ref()
        .expect("changed result should contain delta information");

    assert_eq!(delta.state(), Some(DeltaState::Changed));

    let previous = delta
        .previous_result()
        .expect("changed result should contain previous result");

    assert_eq!(previous.id.as_deref(), Some("previous-result"));
    assert_eq!(previous.name.as_deref(), Some("Example compliance check"));
    assert_eq!(previous.compliance.as_deref(), Some("no"));

    assert_eq!(
        previous.description.as_deref(),
        Some("Compliant:    NO\nActual Value: None")
    );

    let diff = delta
        .diff
        .as_deref()
        .expect("changed result should contain diff");

    assert!(diff.contains("@@ -1,2 +1,2 @@"));
    assert!(diff.contains("-Compliant:    NO"));
    assert!(diff.contains("-Actual Value: None"));
    assert!(diff.contains("+Compliant:    INCOMPLETE"));
    assert!(diff.contains("+Actual Value: Error"));
}

#[test]
fn parse_inner_delta_report_parses_simple_delta_states() {
    let report =
        parse_inner_report_xml(valid_inner_delta_report_xml()).expect("delta report should parse");

    let results = report.results.as_ref().expect("results should exist");

    let same = results
        .result
        .iter()
        .find(|result| result.id.as_deref() == Some("same-result"))
        .expect("same result should exist");

    let gone = results
        .result
        .iter()
        .find(|result| result.id.as_deref() == Some("gone-result"))
        .expect("gone result should exist");

    let new = results
        .result
        .iter()
        .find(|result| result.id.as_deref() == Some("new-result"))
        .expect("new result should exist");

    assert_eq!(
        same.delta.as_ref().and_then(ResultDelta::state),
        Some(DeltaState::Same)
    );

    assert_eq!(
        gone.delta.as_ref().and_then(ResultDelta::state),
        Some(DeltaState::Gone)
    );

    assert_eq!(
        new.delta.as_ref().and_then(ResultDelta::state),
        Some(DeltaState::New)
    );

    assert!(same.delta.as_ref().unwrap().previous_result().is_none());
    assert!(gone.delta.as_ref().unwrap().previous_result().is_none());
    assert!(new.delta.as_ref().unwrap().previous_result().is_none());
}

#[test]
fn parse_flexible_distinguishes_delta_envelope_from_baseline_report() {
    let envelope = parse_report_xml_flexible(valid_delta_report_envelope_xml())
        .expect("delta report envelope should parse");

    assert_eq!(envelope.id.as_deref(), Some("outer-report"));
    assert_eq!(envelope.report.id.as_deref(), Some("current-report"));
    assert_eq!(envelope.report.report_type.as_deref(), Some("delta"));
    assert!(envelope.report.is_delta_report());

    let baseline = envelope
        .report
        .delta
        .as_ref()
        .and_then(|delta| delta.report.as_ref())
        .expect("baseline report should exist");

    assert_eq!(baseline.id.as_deref(), Some("baseline-report"));
    assert_eq!(baseline.scan_run_status.as_deref(), Some("Done"));
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

fn valid_inner_report_xml() -> &'static str {
    r#"
        <report id="inner-report">
            <scan_run_status>Done</scan_run_status>
            <results>
            </results>
        </report>
    "#
}

fn valid_audit_report_xml() -> &'static str {
    r#"
        <report id="audit-report">
            <scan_run_status>Done</scan_run_status>

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

            <compliance>
                <full>no</full>
                <filtered>no</filtered>
            </compliance>

            <host>
                <ip>127.0.0.1</ip>

                <compliance_count>
                    <page>183</page>

                    <yes>
                        <page>5</page>
                    </yes>

                    <no>
                        <page>1</page>
                    </no>

                    <incomplete>
                        <page>146</page>
                    </incomplete>

                    <undefined>
                        <page>31</page>
                    </undefined>
                </compliance_count>

                <host_compliance>no</host_compliance>
            </host>

            <results>
                <result id="result-1">
                    <name>Example compliance check</name>
                    <compliance>yes</compliance>
                </result>
            </results>
        </report>
    "#
}

fn valid_inner_delta_report_xml() -> &'static str {
    r#"
        <report id="current-report" type="delta">
            <gmp>
                <version>22.8</version>
            </gmp>

            <delta>
                <report id="baseline-report">
                    <scan_run_status>Done</scan_run_status>
                    <timestamp>2026-05-29T08:40:02Z</timestamp>
                    <scan_start>2026-05-29T08:40:23Z</scan_start>
                    <scan_end>2026-05-29T08:51:04Z</scan_end>
                </report>
            </delta>

            <results>
                <result id="changed-result">
                    <name>Example compliance check</name>

                    <description>Compliant:    INCOMPLETE
Actual Value: Error</description>

                    <compliance>incomplete</compliance>

                    <delta>changed<result id="previous-result">
                        <name>Example compliance check</name>

                        <description>Compliant:    NO
Actual Value: None</description>

                        <compliance>no</compliance>
                    </result><diff>@@ -1,2 +1,2 @@
-Compliant:    NO
-Actual Value: None
+Compliant:    INCOMPLETE
+Actual Value: Error</diff></delta>
                </result>

                <result id="same-result">
                    <name>Same result</name>
                    <delta>same</delta>
                </result>

                <result id="gone-result">
                    <name>Gone result</name>
                    <delta>gone</delta>
                </result>

                <result id="new-result">
                    <name>New result</name>
                    <delta>new</delta>
                </result>
            </results>
        </report>
    "#
}

fn valid_delta_report_envelope_xml() -> &'static str {
    r#"
        <report
            id="outer-report"
            content_type="application/xml"
            extension="xml"
        >
            <name>Delta report</name>

            <report id="current-report" type="delta">
                <delta>
                    <report id="baseline-report">
                        <scan_run_status>Done</scan_run_status>
                        <timestamp>2026-05-29T08:40:02Z</timestamp>
                        <scan_start>2026-05-29T08:40:23Z</scan_start>
                        <scan_end>2026-05-29T08:51:04Z</scan_end>
                    </report>
                </delta>

                <scan_run_status>Done</scan_run_status>

                <results>
                    <result id="same-result">
                        <name>Same result</name>
                        <delta>same</delta>
                    </result>
                </results>
            </report>
        </report>
    "#
}
