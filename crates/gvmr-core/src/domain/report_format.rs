use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportFormatSource {
    Feed,
    BuiltIn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendererBackend {
    FeedPipeline,
    Typst,
    NativePdf,
}

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
    pub source: ReportFormatSource,
    pub backend: RendererBackend,
}

impl ReportFormat {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        extension: impl Into<String>,
        content_type: impl Into<String>,
        workdir: PathBuf,
        files: Vec<ReportFormatFile>,
        source: ReportFormatSource,
        backend: RendererBackend,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            extension: extension.into(),
            content_type: content_type.into(),
            workdir,
            files,
            source,
            backend,
        }
    }

    pub fn feed(
        id: impl Into<String>,
        name: impl Into<String>,
        extension: impl Into<String>,
        content_type: impl Into<String>,
        workdir: PathBuf,
        files: Vec<ReportFormatFile>,
    ) -> Self {
        Self::new(
            id,
            name,
            extension,
            content_type,
            workdir,
            files,
            ReportFormatSource::Feed,
            RendererBackend::FeedPipeline,
        )
    }

    pub fn built_in_typst(
        id: impl Into<String>,
        name: impl Into<String>,
        extension: impl Into<String>,
        content_type: impl Into<String>,
        workdir: PathBuf,
    ) -> Self {
        Self::new(
            id,
            name,
            extension,
            content_type,
            workdir,
            Vec::new(),
            ReportFormatSource::BuiltIn,
            RendererBackend::Typst,
        )
    }

    pub fn built_in_native_pdf(
        id: impl Into<String>,
        name: impl Into<String>,
        extension: impl Into<String>,
        content_type: impl Into<String>,
        workdir: PathBuf,
    ) -> Self {
        Self::new(
            id,
            name,
            extension,
            content_type,
            workdir,
            Vec::new(),
            ReportFormatSource::BuiltIn,
            RendererBackend::NativePdf,
        )
    }
}
