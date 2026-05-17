use quick_xml::{Reader, de::from_str, events::Event};
use thiserror::Error;

use crate::domain::report_model::ReportEnvelope;

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

pub fn parse_report_xml(report_xml: &str) -> Result<ReportEnvelope, ReportXmlValidationError> {
    validate_report_root(report_xml)?;

    let envelope: ReportEnvelope = from_str(report_xml)
        .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

    validate_report_envelope(&envelope)?;

    Ok(envelope)
}

pub fn validate_report_xml(report_xml: &str) -> Result<(), ReportXmlValidationError> {
    validate_report_root(report_xml)?;

    let envelope: ReportEnvelope = from_str(report_xml)
        .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

    validate_report_envelope(&envelope)
}

fn validate_report_envelope(envelope: &ReportEnvelope) -> Result<(), ReportXmlValidationError> {
    if envelope
        .report
        .id
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err(ReportXmlValidationError::InvalidStructure(
            "inner report id is missing".to_string(),
        ));
    }

    Ok(())
}

fn validate_report_root(report_xml: &str) -> Result<(), ReportXmlValidationError> {
    let mut reader = Reader::from_str(report_xml);
    reader.config_mut().trim_text(false);

    let mut seen_root = false;
    let mut root_depth = 0usize;
    let mut root_closed = false;

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

                return Ok(());
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
