use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::cli::CliRendererType;

use super::render_xml_file;

fn temp_test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX epoch")
        .as_nanos();

    let path = std::env::temp_dir().join(format!(
        "gvmr-lite-rs-cli-render-{name}-{}-{nanos}",
        std::process::id()
    ));

    fs::create_dir_all(&path).expect("test temp dir should be created");
    path
}

fn write_xml(path: &Path, xml: &str) {
    fs::write(path, xml).expect("test XML should be written");
}

fn minimal_report_xml() -> &'static str {
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
    "#
}

fn host_report_xml() -> &'static str {
    r#"
    <report>
        <report id="inner-report-id">
            <scan_run_status>Done</scan_run_status>

            <task>
                <name>CLI Test Task</name>
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
                <full>1</full>
                <filtered>1</filtered>
            </result_count>

            <results>
                <result id="result-1">
                    <host>192.0.2.10</host>
                    <port>443/tcp</port>
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
                    </nvt>
                </result>
            </results>
        </report>
    </report>
    "#
}

#[test]
fn render_xml_file_native_writes_pdf_output() {
    let dir = temp_test_dir("native-success");
    let xml_path = dir.join("report.xml");
    let output_path = dir.join("report.pdf");

    write_xml(&xml_path, minimal_report_xml());

    render_xml_file(CliRendererType::Native, &xml_path, &output_path)
        .expect("native PDF render should succeed");

    let bytes = fs::read(&output_path).expect("output PDF should be readable");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn render_xml_file_native_writes_host_report_pdf_output() {
    let dir = temp_test_dir("native-host-success");
    let xml_path = dir.join("report.xml");
    let output_path = dir.join("report.pdf");

    write_xml(&xml_path, host_report_xml());

    render_xml_file(CliRendererType::Native, &xml_path, &output_path)
        .expect("native PDF render should succeed");

    let bytes = fs::read(&output_path).expect("output PDF should be readable");

    assert!(bytes.starts_with(b"%PDF"));
    assert!(!bytes.is_empty());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn render_xml_file_returns_io_error_when_input_file_is_missing() {
    let dir = temp_test_dir("missing-input");
    let xml_path = dir.join("missing.xml");
    let output_path = dir.join("report.pdf");

    let error = render_xml_file(CliRendererType::Native, &xml_path, &output_path)
        .expect_err("missing input should fail");

    let message = error.to_string();

    assert!(message.contains("read XML file"));
    assert!(message.contains("missing.xml"));
    assert!(!output_path.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn render_xml_file_returns_xml_error_for_invalid_report_xml() {
    let dir = temp_test_dir("invalid-xml");
    let xml_path = dir.join("invalid.xml");
    let output_path = dir.join("report.pdf");

    write_xml(&xml_path, "<foo></foo>");

    let error = render_xml_file(CliRendererType::Native, &xml_path, &output_path)
        .expect_err("invalid XML should fail");

    let message = error.to_string();

    assert!(message.contains("invalid report XML"));
    assert!(message.contains("invalid.xml"));
    assert!(!output_path.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn render_xml_file_returns_io_error_when_output_path_parent_is_missing() {
    let dir = temp_test_dir("missing-output-parent");
    let xml_path = dir.join("report.xml");
    let output_path = dir.join("missing-parent").join("report.pdf");

    write_xml(&xml_path, minimal_report_xml());

    let error = render_xml_file(CliRendererType::Native, &xml_path, &output_path)
        .expect_err("missing output parent should fail");

    let message = error.to_string();

    assert!(message.contains("write output PDF"));
    assert!(message.contains("report.pdf"));
    assert!(!output_path.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn render_xml_file_overwrites_existing_output_file() {
    let dir = temp_test_dir("overwrite-output");
    let xml_path = dir.join("report.xml");
    let output_path = dir.join("report.pdf");

    write_xml(&xml_path, minimal_report_xml());
    fs::write(&output_path, b"old content").expect("old output should be written");

    render_xml_file(CliRendererType::Native, &xml_path, &output_path)
        .expect("native PDF render should succeed");

    let bytes = fs::read(&output_path).expect("output PDF should be readable");

    assert!(bytes.starts_with(b"%PDF"));
    assert_ne!(bytes, b"old content");

    let _ = fs::remove_dir_all(dir);
}
