use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::error::CliError;

#[derive(Debug, Parser)]
#[command(name = "gvmr-cli")]
#[command(about = "Render GVM reports from the command line")]
pub struct Cli {
    /// XML report file to render. Supports full report envelope XML or inner report XML.
    #[arg(long)]
    pub xml: Option<PathBuf>,

    /// Renderer type to use for CLI rendering.
    #[arg(long = "type", value_enum)]
    pub renderer_type: Option<CliRendererType>,

    /// Output PDF path. Defaults to report.pdf.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliRendererType {
    Native,
    Typst,
}

impl Cli {
    pub fn validate(&self) -> Result<(), CliError> {
        if self.xml.is_none() {
            return Err(CliError::Validation(
                "missing --xml <report.xml>".to_string(),
            ));
        }

        if self.renderer_type.is_none() {
            return Err(CliError::Validation(
                "missing --type <native|typst>".to_string(),
            ));
        }

        Ok(())
    }

    pub fn output_path(&self) -> PathBuf {
        self.output
            .clone()
            .unwrap_or_else(|| PathBuf::from("report.pdf"))
    }
}

pub async fn run(cli: Cli) -> Result<(), CliError> {
    cli.validate()?;

    let xml_path = cli.xml.as_ref().expect("validated cli xml path");
    let renderer_type = cli.renderer_type.expect("validated cli renderer type");
    let output_path = cli.output_path();

    crate::cli_render::render_xml_file(renderer_type, xml_path, &output_path)?;

    Ok(())
}
