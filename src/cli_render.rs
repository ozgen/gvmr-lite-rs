use std::{fs, path::Path};

use tracing::info;

use crate::{
    app::error::AppError,
    cli::CliRendererType,
    service::{native_pdf::NativePdfRenderer, typst::renderer::TypstReportRenderer},
    xml::report_validator::parse_report_xml_flexible,
};

pub fn render_xml_file(
    renderer_type: CliRendererType,
    xml_path: &Path,
    output_path: &Path,
) -> Result<(), AppError> {
    let report_xml = fs::read_to_string(xml_path).map_err(|err| {
        AppError::Config(format!(
            "failed to read XML file {}: {err}",
            xml_path.display()
        ))
    })?;

    let report = parse_report_xml_flexible(&report_xml).map_err(|err| {
        AppError::Config(format!("invalid report XML {}: {err}", xml_path.display()))
    })?;

    let pdf = match renderer_type {
        CliRendererType::Native => {
            let renderer = NativePdfRenderer::new();

            renderer
                .render(&report)
                .map_err(|err| AppError::Config(format!("native PDF render failed: {err}")))?
        }

        CliRendererType::Typst => {
            let renderer = TypstReportRenderer::technical_report();

            renderer
                .render(&report)
                .map_err(|err| AppError::Config(format!("Typst render failed: {err}")))?
        }
    };

    fs::write(output_path, pdf).map_err(|err| {
        AppError::Config(format!(
            "failed to write output PDF {}: {err}",
            output_path.display()
        ))
    })?;

    info!(
        renderer = ?renderer_type,
        input = %xml_path.display(),
        output = %output_path.display(),
        "PDF rendered"
    );

    Ok(())
}
