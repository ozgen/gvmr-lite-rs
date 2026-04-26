use std::{fs, path::Path};

use base64::{Engine, engine::general_purpose};
use quick_xml::{Reader, encoding::EncodingError, events::Event};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportFormatParseError {
    #[error("failed to read report format XML: {0}")]
    Read(#[from] std::io::Error),

    #[error("invalid XML: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("invalid XML encoding: {0}")]
    Encoding(#[from] EncodingError),

    #[error("missing required attribute: {0}")]
    MissingAttribute(&'static str),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid base64 for file '{file_name}': {source}")]
    InvalidBase64 {
        file_name: String,
        source: base64::DecodeError,
    },
}

#[derive(Debug, Clone)]
pub struct ParsedReportFormatFile {
    pub name: String,
    pub content: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ParsedReportFormat {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub content_type: String,
    pub report_type: String,
    pub files: Vec<ParsedReportFormatFile>,
}

pub fn parse_report_format_xml(path: &Path) -> Result<ParsedReportFormat, ReportFormatParseError> {
    let xml = fs::read_to_string(path)?;

    let mut reader = Reader::from_str(&xml);
    reader.config_mut().trim_text(true);

    let mut id = None;
    let mut name = String::new();
    let mut extension = String::new();
    let mut content_type = String::new();
    let mut report_type = String::new();

    let mut files = Vec::new();

    let mut current_tag = String::new();
    let mut current_file_name: Option<String> = None;
    let mut current_file_text = String::new();

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                current_tag = String::from_utf8_lossy(event.name().as_ref()).to_string();

                if id.is_none() && current_tag == "report_format" {
                    for attr in event.attributes().flatten() {
                        if attr.key.as_ref() == b"id" {
                            id = Some(
                                attr.decode_and_unescape_value(reader.decoder())?
                                    .to_string(),
                            );
                        }
                    }
                }

                if current_tag == "file" {
                    current_file_name = None;
                    current_file_text.clear();

                    for attr in event.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            current_file_name = Some(
                                attr.decode_and_unescape_value(reader.decoder())?
                                    .to_string(),
                            );
                        }
                    }

                    if current_file_name.is_none() {
                        return Err(ReportFormatParseError::MissingAttribute("file@name"));
                    }
                }
            }

            Event::Text(text) => {
                let value = text.decode()?.trim().to_string();

                if current_tag == "file" {
                    current_file_text.push_str(&value);
                    continue;
                }

                match current_tag.as_str() {
                    "name" => name = value.to_owned(),
                    "extension" => extension = value.to_owned(),
                    "content_type" => content_type = value.to_owned(),
                    "report_type" => report_type = value.to_owned(),
                    _ => {}
                }
            }

            Event::End(event) => {
                let tag = String::from_utf8_lossy(event.name().as_ref()).to_string();

                if tag == "file" {
                    let file_name = current_file_name
                        .take()
                        .ok_or(ReportFormatParseError::MissingAttribute("file@name"))?;

                    let raw = current_file_text.trim();

                    let content = if raw.is_empty() {
                        None
                    } else {
                        Some(general_purpose::STANDARD.decode(raw).map_err(|source| {
                            ReportFormatParseError::InvalidBase64 {
                                file_name: file_name.clone(),
                                source,
                            }
                        })?)
                    };

                    files.push(ParsedReportFormatFile {
                        name: file_name,
                        content,
                    });

                    current_file_text.clear();
                }

                current_tag.clear();
            }

            Event::Eof => break,
            _ => {}
        }
    }

    if files.is_empty() {
        return Err(ReportFormatParseError::MissingField("file"));
    }

    Ok(ParsedReportFormat {
        id: id.ok_or(ReportFormatParseError::MissingAttribute("report_format@id"))?,
        name,
        extension,
        content_type,
        report_type: if report_type.is_empty() {
            "scan".to_string()
        } else {
            report_type
        },
        files,
    })
}

#[cfg(test)]
#[path = "report_format_parser_tests.rs"]
mod report_format_parser_tests;
