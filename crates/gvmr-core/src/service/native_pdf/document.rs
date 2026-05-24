use std::collections::BTreeMap;

use fpdf::{Fpdf, Orientation, PageSize, Pdf, RGB, Unit, UnitVec2};

use crate::domain::report_model::ReportEnvelope;

use crate::service::report_view::{ReportTargetKind, ReportView};

use super::{
    constants::{
        BOTTOM_MARGIN_MM, CONTENT_WIDTH_MM, LEFT_MARGIN_MM, RIGHT_MARGIN_MM, TOP_MARGIN_MM,
    },
    error::NativePdfRenderError,
    grouping::FindingKey,
    toc::TocEntry,
};

pub(crate) struct NativePdfDocument<'a> {
    pub(crate) pdf: Fpdf<'a>,
    pub(crate) report: &'a ReportEnvelope,
    pub(crate) view: ReportView<'a>,
    pub(crate) target: ReportTargetKind,
    pub(crate) host_links: BTreeMap<String, usize>,
    pub(crate) finding_links: BTreeMap<FindingKey, usize>,
    pub(crate) toc: Vec<TocEntry>,
}

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn new(report: &'a ReportEnvelope) -> Self {
        let mut pdf = Fpdf::new(Orientation::Portrait, PageSize::A4, "", UnitVec2::default());

        pdf.set_margins(
            Unit::mm(LEFT_MARGIN_MM),
            Unit::mm(TOP_MARGIN_MM),
            Unit::mm(RIGHT_MARGIN_MM),
        );
        pdf.set_auto_page_break(true, Unit::mm(BOTTOM_MARGIN_MM));
        pdf.alias_nb_pages("");

        pdf.set_header_fn(|pdf| {
            if pdf.page_no() <= 1 {
                return;
            }

            pdf.set_y(Unit::mm(9.0));
            pdf.set_font("Helvetica", "I", Unit::pt(8.0));
            pdf.set_text_color(RGB::new(70, 70, 70));

            pdf.cell_format(
                Unit::mm(120.0),
                Unit::mm(5.0),
                "Scan Report",
                "",
                0,
                "L",
                false,
                0,
                "",
            );

            pdf.cell_format(
                Unit::mm(60.0),
                Unit::mm(5.0),
                &pdf.page_no().to_string(),
                "",
                1,
                "R",
                false,
                0,
                "",
            );

            pdf.ln(Unit::mm(4.0));
            pdf.set_text_color(RGB::new(0, 0, 0));
        });

        pdf.set_footer_fn(|pdf| {
            pdf.set_y(Unit::mm(-15.0));
            pdf.set_font("Helvetica", "I", Unit::pt(8.0));
            pdf.set_text_color(RGB::new(80, 80, 80));

            let text = format!("{} / {{nb}}", pdf.page_no());

            pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM),
                Unit::mm(8.0),
                &text,
                "",
                0,
                "C",
                false,
                0,
                "",
            );

            pdf.set_text_color(RGB::new(0, 0, 0));
        });

        let view = ReportView::from_report(&report.report);
        let target = view.target_kind();

        Self {
            pdf,
            report,
            view,
            target,
            host_links: BTreeMap::new(),
            finding_links: BTreeMap::new(),
            toc: Vec::new(),
        }
    }

    pub(crate) fn render(&mut self) -> Result<Vec<u8>, NativePdfRenderError> {
        self.write_cover();
        self.write_result_overview();
        self.write_results_per_host();

        self.output()
    }

    pub(crate) fn set_link_here(&mut self, link: usize, page: usize) {
        let y = self.pdf.get_y();
        let safe_y = if y.to_mm() < 0.0 { Unit::mm(0.0) } else { y };

        self.pdf.set_link(Some(safe_y), link, Some(page));
    }
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod document_tests;
