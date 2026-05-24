use std::{fs, path::Path};

use tracing::info;

use crate::{cli::CliRendererType, error::CliError};

use gvmr_core::{
    service::{native_pdf::NativePdfRenderer, typst::renderer::TypstReportRenderer},
    xml::report_validator::parse_report_xml_flexible,
};

pub fn render_xml_file(
    renderer_type: CliRendererType,
    xml_path: &Path,
    output_path: &Path,
) -> Result<(), CliError> {
    let report_xml = fs::read_to_string(xml_path).map_err(|source| CliError::Io {
        action: "read XML file",
        path: xml_path.display().to_string(),
        source,
    })?;

    let report = parse_report_xml_flexible(&report_xml).map_err(|err| {
        CliError::Xml(format!("invalid report XML {}: {err}", xml_path.display()))
    })?;

    let pdf = match renderer_type {
        CliRendererType::Native => {
            let renderer = NativePdfRenderer::new();

            renderer.render(&report).map_err(|err| CliError::Render {
                renderer: "native PDF",
                message: err.to_string(),
            })?
        }

        CliRendererType::Typst => {
            let renderer = TypstReportRenderer::technical_report();

            renderer.render(&report).map_err(|err| CliError::Render {
                renderer: "Typst",
                message: err.to_string(),
            })?
        }
    };

    fs::write(output_path, pdf).map_err(|source| CliError::Io {
        action: "write output PDF",
        path: output_path.display().to_string(),
        source,
    })?;

    info!(
        renderer = ?renderer_type,
        input = %xml_path.display(),
        output = %output_path.display(),
        "PDF rendered"
    );

    Ok(())
}

#[cfg(test)]
#[path = "cli_render_tests.rs"]
mod cli_render_tests;
