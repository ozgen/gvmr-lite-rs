use quick_xml::{Reader, de::from_str, events::Event};
use thiserror::Error;

use crate::domain::report_model::{InnerReport, ReportEnvelope};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReportXmlValidationError {
    #[error("empty XML document")]
    EmptyDocument,

    #[error("root element must be <report>")]
    InvalidRootElement,

    #[error("text found before root <report> element")]
    TextBeforeRootElement,

    #[error("invalid XML: {0}")]
    InvalidXml(String),

    #[error("invalid report structure: {0}")]
    InvalidStructure(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportXmlShape {
    Envelope,
    Inner,
}

/// Strict old behavior:
/// accepts only:
///
/// <report>
///   ...
///   <report>
///     inner report
///   </report>
/// </report>
pub fn parse_report_xml(report_xml: &str) -> Result<ReportEnvelope, ReportXmlValidationError> {
    let shape = validate_report_root_and_detect_shape(report_xml)?;

    if shape != ReportXmlShape::Envelope {
        return Err(ReportXmlValidationError::InvalidStructure(
            "expected report envelope with nested inner report".to_string(),
        ));
    }

    let envelope: ReportEnvelope = from_str(report_xml)
        .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

    validate_report_envelope(&envelope)?;

    Ok(envelope)
}

/// New flexible behavior:
/// accepts both full envelope XML and inner report XML.
///
/// Full envelope:
///
/// <report>
///   ...
///   <report>
///     inner report
///   </report>
/// </report>
///
/// Inner report directly:
///
/// <report>
///   scan data directly
/// </report>
pub fn parse_report_xml_flexible(
    report_xml: &str,
) -> Result<ReportEnvelope, ReportXmlValidationError> {
    match validate_report_root_and_detect_shape(report_xml)? {
        ReportXmlShape::Envelope => {
            let envelope: ReportEnvelope = from_str(report_xml)
                .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

            validate_report_envelope(&envelope)?;

            Ok(envelope)
        }

        ReportXmlShape::Inner => {
            let inner: InnerReport = from_str(report_xml)
                .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

            validate_inner_report(&inner)?;

            Ok(ReportEnvelope {
                report: inner,
                ..ReportEnvelope::default()
            })
        }
    }
}

/// New normalized behavior:
/// accepts both full envelope XML and inner report XML,
/// and returns only the inner report.
pub fn parse_inner_report_xml(report_xml: &str) -> Result<InnerReport, ReportXmlValidationError> {
    match validate_report_root_and_detect_shape(report_xml)? {
        ReportXmlShape::Envelope => {
            let envelope: ReportEnvelope = from_str(report_xml)
                .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

            validate_report_envelope(&envelope)?;

            Ok(envelope.report)
        }

        ReportXmlShape::Inner => {
            let inner: InnerReport = from_str(report_xml)
                .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

            validate_inner_report(&inner)?;

            Ok(inner)
        }
    }
}

/// Strict old validation:
/// only full envelope XML is accepted.
pub fn validate_report_xml(report_xml: &str) -> Result<(), ReportXmlValidationError> {
    let shape = validate_report_root_and_detect_shape(report_xml)?;

    if shape != ReportXmlShape::Envelope {
        return Err(ReportXmlValidationError::InvalidStructure(
            "expected report envelope with nested inner report".to_string(),
        ));
    }

    let envelope: ReportEnvelope = from_str(report_xml)
        .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

    validate_report_envelope(&envelope)
}

/// Flexible validation:
/// full envelope XML and inner report XML are both accepted.
pub fn validate_report_xml_flexible(report_xml: &str) -> Result<(), ReportXmlValidationError> {
    match validate_report_root_and_detect_shape(report_xml)? {
        ReportXmlShape::Envelope => {
            let envelope: ReportEnvelope = from_str(report_xml)
                .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

            validate_report_envelope(&envelope)
        }

        ReportXmlShape::Inner => {
            let inner: InnerReport = from_str(report_xml)
                .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

            validate_inner_report(&inner)
        }
    }
}

fn validate_report_envelope(envelope: &ReportEnvelope) -> Result<(), ReportXmlValidationError> {
    validate_inner_report(&envelope.report)
}

fn validate_inner_report(inner: &InnerReport) -> Result<(), ReportXmlValidationError> {
    if inner.id.as_deref().unwrap_or("").trim().is_empty() {
        return Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string(),
        ));
    }

    Ok(())
}

fn validate_report_root_and_detect_shape(
    report_xml: &str,
) -> Result<ReportXmlShape, ReportXmlValidationError> {
    let mut reader = Reader::from_str(report_xml);
    reader.config_mut().trim_text(false);

    let mut seen_root = false;
    let mut root_depth = 0usize;
    let mut root_closed = false;
    let mut has_direct_nested_report = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                if root_closed {
                    return Err(ReportXmlValidationError::InvalidXml(
                        "multiple root elements found".to_string(),
                    ));
                }

                if !seen_root {
                    if start.name().as_ref() != b"report" {
                        return Err(ReportXmlValidationError::InvalidRootElement);
                    }

                    seen_root = true;
                    root_depth = 1;
                    continue;
                }

                if root_depth == 1 && start.name().as_ref() == b"report" {
                    has_direct_nested_report = true;
                }

                root_depth += 1;
            }

            Ok(Event::Empty(start)) => {
                if root_closed {
                    return Err(ReportXmlValidationError::InvalidXml(
                        "multiple root elements found".to_string(),
                    ));
                }

                if !seen_root {
                    if start.name().as_ref() != b"report" {
                        return Err(ReportXmlValidationError::InvalidRootElement);
                    }

                    seen_root = true;
                    root_closed = true;
                    continue;
                }

                if root_depth == 1 && start.name().as_ref() == b"report" {
                    has_direct_nested_report = true;
                }
            }

            Ok(Event::End(_)) => {
                root_depth = root_depth.saturating_sub(1);

                if seen_root && root_depth == 0 {
                    root_closed = true;
                }
            }

            Ok(Event::Decl(_))
            | Ok(Event::Comment(_))
            | Ok(Event::DocType(_))
            | Ok(Event::PI(_)) => {
                continue;
            }

            Ok(Event::Text(text)) => {
                let value = text
                    .decode()
                    .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

                if value.trim().is_empty() {
                    continue;
                }

                if !seen_root {
                    return Err(ReportXmlValidationError::TextBeforeRootElement);
                }

                if root_closed {
                    return Err(ReportXmlValidationError::InvalidXml(
                        "text found after root element".to_string(),
                    ));
                }
            }

            Ok(Event::Eof) => {
                if !seen_root {
                    return Err(ReportXmlValidationError::EmptyDocument);
                }

                if root_depth != 0 {
                    return Err(ReportXmlValidationError::InvalidXml(
                        "unexpected EOF before closing root element".to_string(),
                    ));
                }

                return Ok(if has_direct_nested_report {
                    ReportXmlShape::Envelope
                } else {
                    ReportXmlShape::Inner
                });
            }

            Err(err) => {
                return Err(ReportXmlValidationError::InvalidXml(err.to_string()));
            }

            _ => {
                continue;
            }
        }
    }
}

#[cfg(test)]
#[path = "report_validator_tests.rs"]
mod report_validator_tests;
