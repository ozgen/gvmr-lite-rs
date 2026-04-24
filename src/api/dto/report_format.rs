use serde::Serialize;
use utoipa::ToSchema;

use crate::domain::report_format::ReportFormat;

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportFormatFileResponse {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportFormatResponse {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub content_type: String,
    pub workdir: String,
    pub files: Vec<ReportFormatFileResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportFormatListResponse {
    pub count: usize,
    pub items: Vec<ReportFormatResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportFormatSyncResponse {
    pub status: &'static str,
    pub count: usize,
}

impl From<&ReportFormat> for ReportFormatResponse {
    fn from(fmt: &ReportFormat) -> Self {
        Self {
            id: fmt.id.clone(),
            name: fmt.name.clone(),
            extension: fmt.extension.clone(),
            content_type: fmt.content_type.clone(),
            workdir: fmt.workdir.display().to_string(),
            files: fmt
                .files
                .iter()
                .map(|f| ReportFormatFileResponse {
                    name: f.name.clone(),
                    path: f.path.display().to_string(),
                })
                .collect(),
        }
    }
}
