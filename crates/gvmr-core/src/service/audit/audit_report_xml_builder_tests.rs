use super::build_audit_report_xml;

use serde_json::json;

use crate::domain::audit_report_model::AuditReportEnvelope;

fn valid_audit_report() -> AuditReportEnvelope {
    serde_json::from_value(json!({
        "@attrs": {
            "id": "outer-report"
        },
        "name": "Audit Report",
        "report": {
            "scan_run_status": "Done",
            "timestamp": "2026-06-04T10:00:00Z",
            "results": {
                "result": []
            }
        }
    }))
    .expect("valid audit report should deserialize")
}

#[test]
fn build_audit_report_xml_serializes_audit_report_envelope() {
    let report = valid_audit_report();

    let xml = build_audit_report_xml(&report).expect("audit report XML should be built");

    assert!(xml.contains("<report"));
    assert!(xml.contains("Audit Report"));
    assert!(xml.contains("scan_run_status"));
    assert!(xml.contains("Done"));
}
