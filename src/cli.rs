use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "gvmr-lite-rs")]
#[command(about = "GVM report rendering service and CLI")]
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
    pub fn is_render_mode(&self) -> bool {
        self.xml.is_some() || self.renderer_type.is_some() || self.output.is_some()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.is_render_mode() {
            return Ok(());
        }

        if self.xml.is_none() {
            return Err("missing --xml <report.xml>".to_string());
        }

        if self.renderer_type.is_none() {
            return Err("missing --type <native|typst>".to_string());
        }

        Ok(())
    }

    pub fn output_path(&self) -> PathBuf {
        self.output
            .clone()
            .unwrap_or_else(|| PathBuf::from("report.pdf"))
    }
}
