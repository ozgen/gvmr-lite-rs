use crate::{
    domain::report_model::ReportEnvelope, service::native_pdf::renderer::NativePdfRenderer,
    xml::report_validator::parse_report_xml_flexible,
};

fn parse_report(xml: &str) -> ReportEnvelope {
    parse_report_xml_flexible(xml).expect("test report XML should parse")
}

fn minimal_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <result_count>
                    <full>0</full>
                    <filtered>0</filtered>
                </result_count>
                <results />
            </report>
        </report>
        "#,
    )
}

fn delta_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="current-report" type="delta">
                <delta>
                    <report id="baseline-report">
                        <scan_run_status>Done</scan_run_status>
                    </report>
                </delta>
                <result_count><full>1</full><filtered>1</filtered></result_count>
                <results>
                    <result id="current-result">
                        <host>192.0.2.10</host>
                        <name>Changed finding</name>
                        <threat>High</threat>
                        <severity>8.0</severity>
                        <delta>changed<result id="previous-result"><host>192.0.2.10</host><name>Previous finding</name></result><diff>@@ -1 +1 @@
-before
+after</diff></delta>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn compliance_delta_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="current-compliance-report" type="delta">
                <delta>
                    <report id="baseline-compliance-report">
                        <scan_run_status>Done</scan_run_status>
                    </report>
                </delta>
                <compliance_count><filtered>1</filtered><yes><filtered>1</filtered></yes></compliance_count>
                <results>
                    <result id="current-result">
                        <host>192.0.2.10</host>
                        <name>Changed check</name>
                        <compliance>yes</compliance>
                        <delta>changed<result id="previous-result"><host>192.0.2.10</host><name>Previous check</name><compliance>no</compliance></result><diff>@@ -1 +1 @@
-no
+yes</diff></delta>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn host_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <task>
                    <name>Test Task</name>
                </task>

                <host>
                    <ip>192.0.2.10</ip>
                    <start>2024-01-02T03:04:05Z</start>
                    <end>2024-01-02T04:04:05Z</end>
                    <detail>
                        <name>hostname</name>
                        <value>host-a.example.test</value>
                    </detail>
                </host>

                <result_count>
                    <full>2</full>
                    <filtered>2</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <port>80/tcp</port>
                        <name>High Finding</name>
                        <description>Detected vulnerable service output.</description>
                        <threat>High</threat>
                        <severity>8.0</severity>
                        <qod>
                            <value>80</value>
                        </qod>
                        <nvt oid="1.2.3.4">
                            <name>High NVT</name>
                            <tags>summary=Summary text|impact=Impact text|solution=Solution text</tags>
                            <solution type="VendorFix">Install the vendor update.</solution>
                            <refs>
                                <ref type="url" id="https://example.test/advisory" />
                            </refs>
                        </nvt>
                    </result>

                    <result id="result-2">
                        <host>192.0.2.10</host>
                        <port>443/tcp</port>
                        <name>Low Finding</name>
                        <description>Low risk finding.</description>
                        <threat>Low</threat>
                        <severity>2.0</severity>
                        <qod>
                            <value>70</value>
                        </qod>
                        <nvt oid="1.2.3.5">
                            <name>Low NVT</name>
                            <tags>summary=Low summary|impact=Low impact|solution=Low solution</tags>
                        </nvt>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn agent_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <task>
                    <name>Agent Task</name>
                    <agent_group id="agent-group-id">
                        <name>Test Agent Group</name>
                    </agent_group>
                </task>

                <host>
                    <ip>192.0.2.10</ip>
                    <detail>
                        <name>agentID</name>
                        <value>agent-a</value>
                    </detail>
                </host>

                <result_count>
                    <full>1</full>
                    <filtered>1</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>192.0.2.10</host>
                        <name>Agent Finding</name>
                        <threat>Medium</threat>
                        <severity>5.0</severity>
                        <nvt oid="1.2.3.4">
                            <name>Agent NVT</name>
                            <tags>summary=Agent summary|solution=Agent solution</tags>
                        </nvt>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

fn container_image_report() -> ReportEnvelope {
    parse_report(
        r#"
        <report>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>

                <task>
                    <name>Container Image Task</name>
                    <oci_image_target id="oci-target-id">
                        <name>Container Image Target</name>
                    </oci_image_target>
                </task>

                <result_count>
                    <full>1</full>
                    <filtered>1</filtered>
                </result_count>

                <results>
                    <result id="result-1">
                        <host>sha256:first-digest</host>
                        <name>Container Finding</name>
                        <threat>Critical</threat>
                        <severity>10.0</severity>
                        <oci_image>
                            <name>registry.example.test/team/app:1.0</name>
                            <digest>sha256:first-digest</digest>
                            <registry>registry.example.test</registry>
                            <path>team/app</path>
                            <short_name>app:1.0</short_name>
                        </oci_image>
                        <nvt oid="1.2.3.4">
                            <name>Container NVT</name>
                            <tags>summary=Container summary|solution=Container solution</tags>
                        </nvt>
                    </result>
                </results>
            </report>
        </report>
        "#,
    )
}

#[test]
fn new_returns_default_renderer() {
    let renderer = NativePdfRenderer::new();

    let cloned = renderer.clone();

    assert_eq!(format!("{renderer:?}"), "NativePdfRenderer");
    assert_eq!(format!("{cloned:?}"), "NativePdfRenderer");
}

#[test]
fn default_returns_renderer() {
    let renderer = NativePdfRenderer;

    assert_eq!(format!("{renderer:?}"), "NativePdfRenderer");
}

#[test]
fn render_minimal_report_returns_pdf_bytes() {
    let renderer = NativePdfRenderer::new();
    let report = minimal_report();

    let bytes = renderer
        .render(&report)
        .expect("minimal native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_delta_uses_delta_aware_document_pipeline() {
    let bytes = NativePdfRenderer::new()
        .render_delta(&delta_report())
        .expect("delta native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_compliance_delta_uses_delta_aware_document_pipeline() {
    let bytes = NativePdfRenderer::new()
        .render_compliance_delta(&compliance_delta_report())
        .expect("compliance delta native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_host_report_returns_pdf_bytes() {
    let renderer = NativePdfRenderer::new();
    let report = host_report();

    let bytes = renderer
        .render(&report)
        .expect("host native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_agent_report_returns_pdf_bytes() {
    let renderer = NativePdfRenderer::new();
    let report = agent_report();

    let bytes = renderer
        .render(&report)
        .expect("agent native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_container_image_report_returns_pdf_bytes() {
    let renderer = NativePdfRenderer::new();
    let report = container_image_report();

    let bytes = renderer
        .render(&report)
        .expect("container image native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}

#[test]
fn render_is_repeatable_for_same_report() {
    let renderer = NativePdfRenderer::new();
    let report = host_report();

    let first = renderer
        .render(&report)
        .expect("first native PDF render should succeed");
    let second = renderer
        .render(&report)
        .expect("second native PDF render should succeed");

    assert!(first.starts_with(b"%PDF"));
    assert!(second.starts_with(b"%PDF"));
    assert!(!first.is_empty());
    assert!(!second.is_empty());
}

#[test]
fn render_with_empty_result_set_still_returns_pdf_bytes() {
    let renderer = NativePdfRenderer::new();
    let report = minimal_report();

    let bytes = renderer
        .render(&report)
        .expect("empty result native PDF render should succeed");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());
}
