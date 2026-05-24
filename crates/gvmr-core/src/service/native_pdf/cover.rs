use fpdf::{Pdf, Unit};

use crate::service::pdf_renderer_helper::{
    clean_text, format_report_date, report_date, summary_text,
};

use super::{constants::CONTENT_WIDTH_MM, document::NativePdfDocument};

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn write_cover(&mut self) {
        self.pdf.add_page();

        self.pdf.set_y(Unit::mm(45.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(18.0));
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(10.0),
            "Scan Report",
            "",
            1,
            "C",
            false,
            0,
            "",
        );

        self.pdf.ln(Unit::mm(10.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(11.0));
        let formatted_report_date = format_report_date(&report_date(self.report));

        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(8.0),
            &formatted_report_date,
            "",
            1,
            "C",
            false,
            0,
            "",
        );

        self.pdf.ln(Unit::mm(8.0));
        self.pdf.set_font("Helvetica", "B", Unit::pt(9.0));
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(6.0),
            "Summary",
            "",
            1,
            "C",
            false,
            0,
            "",
        );

        self.pdf.set_x(Unit::mm(35.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(9.0));
        self.pdf.multi_cell(
            Unit::mm(140.0),
            Unit::mm(4.8),
            &clean_text(&summary_text(self.report)),
            "",
            "L",
            false,
        );

        self.pdf.ln(Unit::mm(16.0));
        self.pdf.set_font("Helvetica", "B", Unit::pt(16.0));
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(10.0),
            "Contents",
            "",
            1,
            "L",
            false,
            0,
            "",
        );

        self.pdf.ln(Unit::mm(4.0));

        let toc = self.toc.clone();

        for entry in toc {
            if entry.page == 0 {
                continue;
            }

            self.write_toc_entry(&entry);
        }
    }
}

#[cfg(test)]
#[path = "cover_tests.rs"]
mod cover_tests;
