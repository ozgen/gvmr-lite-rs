use std::{fs, path::Path};

use base64::{Engine, engine::general_purpose};
use quick_xml::{
    Reader,
    encoding::EncodingError,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
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
    parse_report_format_xml_str(&xml)
}

fn parse_report_format_xml_str(xml: &str) -> Result<ParsedReportFormat, ReportFormatParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut state = ReportFormatParseState::default();

    loop {
        match reader.read_event()? {
            Event::Start(event) => handle_start(&mut state, &reader, event)?,
            Event::Text(text) => handle_text(&mut state, text)?,
            Event::End(event) => handle_end(&mut state, event)?,
            Event::Eof => break,
            _ => {}
        }
    }

    state.finish()
}

#[derive(Debug, Default)]
struct ReportFormatParseState {
    id: Option<String>,
    name: String,
    extension: String,
    content_type: String,
    report_type: String,
    files: Vec<ParsedReportFormatFile>,

    current_tag: Option<String>,
    current_file: Option<FileParseState>,
}

#[derive(Debug, Default)]
struct FileParseState {
    name: String,
    text: String,
}

fn handle_start(
    state: &mut ReportFormatParseState,
    reader: &Reader<&[u8]>,
    event: BytesStart<'_>,
) -> Result<(), ReportFormatParseError> {
    let tag = tag_name(event.name().as_ref());
    state.current_tag = Some(tag.clone());

    if tag == "report_format" && state.id.is_none() {
        state.id = read_optional_attr(&event, reader, b"id")?;
    }

    if tag == "file" {
        let file_name = read_optional_attr(&event, reader, b"name")?
            .ok_or(ReportFormatParseError::MissingAttribute("file@name"))?;

        state.current_file = Some(FileParseState {
            name: file_name,
            text: String::new(),
        });
    }

    Ok(())
}

fn handle_text(
    state: &mut ReportFormatParseState,
    text: BytesText<'_>,
) -> Result<(), ReportFormatParseError> {
    let value = text.decode()?.trim().to_string();

    if let Some(file) = state.current_file.as_mut() {
        file.text.push_str(&value);
        return Ok(());
    }

    match state.current_tag.as_deref() {
        Some("name") => state.name = value,
        Some("extension") => state.extension = value,
        Some("content_type") => state.content_type = value,
        Some("report_type") => state.report_type = value,
        _ => {}
    }

    Ok(())
}

fn handle_end(
    state: &mut ReportFormatParseState,
    event: BytesEnd<'_>,
) -> Result<(), ReportFormatParseError> {
    let tag = tag_name(event.name().as_ref());

    if tag == "file" {
        let file = state
            .current_file
            .take()
            .ok_or(ReportFormatParseError::MissingAttribute("file@name"))?;

        let content = decode_file_content(&file.name, &file.text)?;

        state.files.push(ParsedReportFormatFile {
            name: file.name,
            content,
        });
    }

    state.current_tag = None;

    Ok(())
}

fn decode_file_content(
    file_name: &str,
    raw: &str,
) -> Result<Option<Vec<u8>>, ReportFormatParseError> {
    let raw = raw.trim();

    if raw.is_empty() {
        return Ok(None);
    }

    general_purpose::STANDARD
        .decode(raw)
        .map(Some)
        .map_err(|source| ReportFormatParseError::InvalidBase64 {
            file_name: file_name.to_string(),
            source,
        })
}

fn read_optional_attr(
    event: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    attr_name: &[u8],
) -> Result<Option<String>, ReportFormatParseError> {
    for attr in event.attributes().flatten() {
        if attr.key.as_ref() == attr_name {
            let value = attr.decode_and_unescape_value(reader.decoder())?;
            return Ok(Some(value.to_string()));
        }
    }

    Ok(None)
}

fn tag_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).to_string()
}

impl ReportFormatParseState {
    fn finish(self) -> Result<ParsedReportFormat, ReportFormatParseError> {
        if self.files.is_empty() {
            return Err(ReportFormatParseError::MissingField("file"));
        }

        Ok(ParsedReportFormat {
            id: self
                .id
                .ok_or(ReportFormatParseError::MissingAttribute("report_format@id"))?,
            name: self.name,
            extension: self.extension,
            content_type: self.content_type,
            report_type: default_report_type(self.report_type),
            files: self.files,
        })
    }
}

fn default_report_type(report_type: String) -> String {
    if report_type.is_empty() {
        "scan".to_string()
    } else {
        report_type
    }
}

#[cfg(test)]
#[path = "report_format_parser_tests.rs"]
mod report_format_parser_tests;
