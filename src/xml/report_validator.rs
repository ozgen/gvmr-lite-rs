use quick_xml::{Reader, events::Event};
use thiserror::Error;

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
}

pub fn validate_report_xml(report_xml: &str) -> Result<(), ReportXmlValidationError> {
    let mut reader = Reader::from_str(report_xml);
    reader.config_mut().trim_text(false);

    let mut seen_root = false;
    let mut root_depth = 0usize;

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                if !seen_root {
                    if start.name().as_ref() != b"report" {
                        return Err(ReportXmlValidationError::InvalidRootElement);
                    }

                    seen_root = true;
                }

                root_depth += 1;
            }

            Ok(Event::Empty(start)) => {
                if !seen_root {
                    if start.name().as_ref() != b"report" {
                        return Err(ReportXmlValidationError::InvalidRootElement);
                    }

                    seen_root = true;
                }
            }

            Ok(Event::End(_)) => {
                root_depth = root_depth.saturating_sub(1);
            }

            Ok(Event::Decl(_))
            | Ok(Event::Comment(_))
            | Ok(Event::DocType(_))
            | Ok(Event::PI(_)) => {
                continue;
            }

            Ok(Event::Text(text)) => {
                if !seen_root {
                    let value = text
                        .decode()
                        .map_err(|err| ReportXmlValidationError::InvalidXml(err.to_string()))?;

                    if value.trim().is_empty() {
                        continue;
                    }

                    return Err(ReportXmlValidationError::TextBeforeRootElement);
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
