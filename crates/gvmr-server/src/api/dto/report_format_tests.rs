use gvmr_core::domain::report_format::{
    RendererBackend, ReportFormat, ReportFormatFile, ReportFormatSource,
};
use std::path::PathBuf;

use super::{ReportFormatListResponse, ReportFormatResponse, ReportFormatSyncResponse};

#[test]
fn report_format_response_from_report_format_maps_basic_fields() {
    let format = ReportFormat {
        id: "format-1".to_string(),
        name: "PDF Report".to_string(),
        extension: "pdf".to_string(),
        source: ReportFormatSource::Feed,
        backend: RendererBackend::FeedPipeline,
        content_type: "application/pdf".to_string(),
        workdir: PathBuf::from("/tmp/work/format-1"),
        files: vec![],
    };

    let response = ReportFormatResponse::from(&format);

    assert_eq!(response.id, "format-1");
    assert_eq!(response.name, "PDF Report");
    assert_eq!(response.extension, "pdf");
    assert_eq!(response.content_type, "application/pdf");
    assert_eq!(response.workdir, "/tmp/work/format-1");
    assert!(response.files.is_empty());
}

#[test]
fn report_format_response_from_report_format_maps_files() {
    let format = ReportFormat {
        id: "format-1".to_string(),
        name: "PDF Report".to_string(),
        extension: "pdf".to_string(),
        source: ReportFormatSource::Feed,
        backend: RendererBackend::FeedPipeline,
        content_type: "application/pdf".to_string(),
        workdir: PathBuf::from("/tmp/work/format-1"),
        files: vec![
            ReportFormatFile {
                name: "report.xsl".to_string(),
                path: PathBuf::from("/tmp/work/format-1/report.xsl"),
            },
            ReportFormatFile {
                name: "template.tex".to_string(),
                path: PathBuf::from("/tmp/work/format-1/template.tex"),
            },
        ],
    };

    let response = ReportFormatResponse::from(&format);

    assert_eq!(response.files.len(), 2);

    assert_eq!(response.files[0].name, "report.xsl");
    assert_eq!(response.files[0].path, "/tmp/work/format-1/report.xsl");

    assert_eq!(response.files[1].name, "template.tex");
    assert_eq!(response.files[1].path, "/tmp/work/format-1/template.tex");
}

#[test]
fn report_format_list_response_can_hold_items_and_count() {
    let response = ReportFormatListResponse {
        count: 1,
        items: vec![ReportFormatResponse {
            id: "format-1".to_string(),
            name: "PDF Report".to_string(),
            extension: "pdf".to_string(),
            content_type: "application/pdf".to_string(),
            workdir: "/tmp/work/format-1".to_string(),
            files: vec![],
        }],
    };

    assert_eq!(response.count, 1);
    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0].id, "format-1");
}

#[test]
fn report_format_sync_response_can_hold_status_and_count() {
    let response = ReportFormatSyncResponse {
        status: "ok",
        count: 3,
    };

    assert_eq!(response.status, "ok");
    assert_eq!(response.count, 3);
}
