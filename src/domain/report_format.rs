use std::path::PathBuf;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ReportFormatFile {
    pub name: String,
    pub path: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ReportFormat {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub content_type: String,
    pub workdir: PathBuf,
    pub files: Vec<ReportFormatFile>,
}
