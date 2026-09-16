use std::{fs, path::Path};

use tracing::info;

use crate::{cli::CliRendererType, error::CliError};

use gvmr_core::{
    domain::report_format_constants::{
        BUILT_IN_NATIVE_PDF_COMPLIANCE_ID, BUILT_IN_NATIVE_PDF_TECHNICAL_ID,
    },
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
        CliRendererType::Native => render_native_pdf(BUILT_IN_NATIVE_PDF_TECHNICAL_ID, &report)?,
        CliRendererType::NativeCompliance => {
            render_native_pdf(BUILT_IN_NATIVE_PDF_COMPLIANCE_ID, &report)?
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

fn render_native_pdf(
    format_id: &str,
    report: &gvmr_core::domain::report_model::ReportEnvelope,
) -> Result<Vec<u8>, CliError> {
    match format_id {
        BUILT_IN_NATIVE_PDF_TECHNICAL_ID | BUILT_IN_NATIVE_PDF_COMPLIANCE_ID => {
            let pdf = if format_id == BUILT_IN_NATIVE_PDF_COMPLIANCE_ID {
                NativePdfRenderer::new().render_compliance(report)
            } else {
                NativePdfRenderer::new().render_technical(report)
            };

            pdf.map_err(|err| CliError::Render {
                renderer: "native PDF",
                message: err.to_string(),
            })
        }
        _ => Err(CliError::Validation(format!(
            "unsupported native PDF format: {format_id}"
        ))),
    }
}

#[cfg(test)]
#[path = "cli_render_tests.rs"]
mod cli_render_tests;
