use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ReportFormatFile {
    pub name: String,
    pub path: PathBuf,
}

impl ReportFormatFile {
    pub fn new(name: impl Into<String>, path: PathBuf) -> Self {
        Self {
            name: name.into(),
            path,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportFormat {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub content_type: String,
    pub workdir: PathBuf,
    pub files: Vec<ReportFormatFile>,
}

impl ReportFormat {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        extension: impl Into<String>,
        content_type: impl Into<String>,
        workdir: PathBuf,
        files: Vec<ReportFormatFile>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            extension: extension.into(),
            content_type: content_type.into(),
            workdir,
            files,
        }
    }
}
