use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;

use crate::{
    cli::{Cli, CliRendererType},
    error::CliError,
};

fn temp_test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX epoch")
        .as_nanos();

    let path = std::env::temp_dir().join(format!(
        "gvmr-lite-rs-cli-{name}-{}-{nanos}",
        std::process::id()
    ));

    fs::create_dir_all(&path).expect("test temp dir should be created");
    path
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

#[test]
fn parse_cli_accepts_xml_type_and_output() {
    let cli = Cli::parse_from([
        "gvmr-cli",
        "--xml",
        "report.xml",
        "--type",
        "native",
        "--output",
        "out.pdf",
    ]);

    assert_eq!(cli.xml, Some(PathBuf::from("report.xml")));
    assert_eq!(cli.renderer_type, Some(CliRendererType::Native));
    assert_eq!(cli.output, Some(PathBuf::from("out.pdf")));
}

#[test]
fn parse_cli_accepts_short_output_flag() {
    let cli = Cli::parse_from([
        "gvmr-cli",
        "--xml",
        "report.xml",
        "--type",
        "typst",
        "-o",
        "out.pdf",
    ]);

    assert_eq!(cli.xml, Some(PathBuf::from("report.xml")));
    assert_eq!(cli.renderer_type, Some(CliRendererType::Typst));
    assert_eq!(cli.output, Some(PathBuf::from("out.pdf")));
}

#[test]
fn parse_cli_accepts_missing_optional_values() {
    let cli = Cli::parse_from(["gvmr-cli"]);

    assert_eq!(cli.xml, None);
    assert_eq!(cli.renderer_type, None);
    assert_eq!(cli.output, None);
}

#[test]
fn parse_cli_rejects_unknown_renderer_type() {
    let error = Cli::try_parse_from(["gvmr-cli", "--xml", "report.xml", "--type", "unknown"])
        .expect_err("unknown renderer type should fail clap parsing");

    let message = error.to_string();

    assert!(message.contains("invalid value"));
    assert!(message.contains("unknown"));
}

#[test]
fn validate_accepts_xml_and_renderer_type() {
    let cli = Cli {
        xml: Some(PathBuf::from("report.xml")),
        renderer_type: Some(CliRendererType::Native),
        output: None,
    };

    assert!(cli.validate().is_ok());
}

#[test]
fn validate_returns_error_when_xml_is_missing() {
    let cli = Cli {
        xml: None,
        renderer_type: Some(CliRendererType::Native),
        output: None,
    };

    let error = cli.validate().expect_err("missing XML should fail");

    assert!(matches!(error, CliError::Validation(_)));
    assert_eq!(error.to_string(), "missing --xml <report.xml>");
}

#[test]
fn validate_returns_error_when_renderer_type_is_missing() {
    let cli = Cli {
        xml: Some(PathBuf::from("report.xml")),
        renderer_type: None,
        output: None,
    };

    let error = cli
        .validate()
        .expect_err("missing renderer type should fail");

    assert!(matches!(error, CliError::Validation(_)));
    assert_eq!(error.to_string(), "missing --type <native|typst>");
}

#[test]
fn validate_checks_xml_before_renderer_type() {
    let cli = Cli {
        xml: None,
        renderer_type: None,
        output: None,
    };

    let error = cli.validate().expect_err("missing XML should fail first");

    assert!(matches!(error, CliError::Validation(_)));
    assert_eq!(error.to_string(), "missing --xml <report.xml>");
}

#[test]
fn output_path_returns_explicit_output_path() {
    let cli = Cli {
        xml: Some(PathBuf::from("report.xml")),
        renderer_type: Some(CliRendererType::Native),
        output: Some(PathBuf::from("custom.pdf")),
    };

    assert_eq!(cli.output_path(), PathBuf::from("custom.pdf"));
}

#[test]
fn output_path_defaults_to_report_pdf() {
    let cli = Cli {
        xml: Some(PathBuf::from("report.xml")),
        renderer_type: Some(CliRendererType::Native),
        output: None,
    };

    assert_eq!(cli.output_path(), PathBuf::from("report.pdf"));
}

#[test]
fn renderer_type_is_copy_clone_debug_and_eq() {
    let renderer_type = CliRendererType::Native;
    let copied = renderer_type;
    let cloned = renderer_type;

    assert_eq!(renderer_type, copied);
    assert_eq!(renderer_type, cloned);
    assert_eq!(format!("{renderer_type:?}"), "Native");
}

#[tokio::test]
async fn run_returns_validation_error_when_xml_is_missing() {
    let cli = Cli {
        xml: None,
        renderer_type: Some(CliRendererType::Native),
        output: None,
    };

    let error = super::run(cli)
        .await
        .expect_err("missing XML should fail before rendering");

    assert!(matches!(error, CliError::Validation(_)));
    assert_eq!(error.to_string(), "missing --xml <report.xml>");
}

#[tokio::test]
async fn run_returns_validation_error_when_renderer_type_is_missing() {
    let cli = Cli {
        xml: Some(PathBuf::from("report.xml")),
        renderer_type: None,
        output: None,
    };

    let error = super::run(cli)
        .await
        .expect_err("missing renderer type should fail before rendering");

    assert!(matches!(error, CliError::Validation(_)));
    assert_eq!(error.to_string(), "missing --type <native|typst>");
}

#[tokio::test]
async fn run_native_writes_pdf_to_default_output_path() {
    let dir = temp_test_dir("run-native-default-output");
    let xml_path = dir.join("report.xml");

    fs::write(&xml_path, minimal_report_xml()).expect("test XML should be written");

    let previous_dir = std::env::current_dir().expect("current dir should be readable");
    std::env::set_current_dir(&dir).expect("test current dir should be set");

    let result = super::run(Cli {
        xml: Some(xml_path),
        renderer_type: Some(CliRendererType::Native),
        output: None,
    })
    .await;

    std::env::set_current_dir(previous_dir).expect("current dir should be restored");

    result.expect("native CLI render should succeed");

    let output_path = dir.join("report.pdf");
    let bytes = fs::read(&output_path).expect("default output PDF should exist");

    assert!(bytes.starts_with(b"%PDF"));

    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn run_native_writes_pdf_to_custom_output_path() {
    let dir = temp_test_dir("run-native-custom-output");
    let xml_path = dir.join("report.xml");
    let output_path = dir.join("custom.pdf");

    fs::write(&xml_path, minimal_report_xml()).expect("test XML should be written");

    super::run(Cli {
        xml: Some(xml_path),
        renderer_type: Some(CliRendererType::Native),
        output: Some(output_path.clone()),
    })
    .await
    .expect("native CLI render should succeed");

    let bytes = fs::read(&output_path).expect("custom output PDF should exist");

    assert!(bytes.starts_with(b"%PDF"));

    let _ = fs::remove_dir_all(dir);
}
