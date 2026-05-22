use fpdf::{Pdf, Unit};

use crate::service::pdf_renderer_helper::clean_text;

use super::{
    constants::{A4_HEIGHT_MM, BOTTOM_MARGIN_MM, CONTENT_WIDTH_MM},
    document::NativePdfDocument,
};

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn write_heading(&mut self, title: &str, level: usize) {
        match level {
            1 => {
                self.pdf.ln(Unit::mm(4.0));
                self.pdf.set_font("Helvetica", "B", Unit::pt(14.0));
                self.pdf.cell_format(
                    Unit::mm(CONTENT_WIDTH_MM),
                    Unit::mm(8.0),
                    &clean_text(title),
                    "",
                    1,
                    "L",
                    false,
                    0,
                    "",
                );
            }
            2 => {
                self.pdf.ln(Unit::mm(3.0));
                self.pdf.set_font("Helvetica", "B", Unit::pt(12.0));
                self.pdf.cell_format(
                    Unit::mm(CONTENT_WIDTH_MM),
                    Unit::mm(7.0),
                    &clean_text(title),
                    "",
                    1,
                    "L",
                    false,
                    0,
                    "",
                );
            }
            _ => {
                self.pdf.ln(Unit::mm(2.0));
                self.pdf.set_font("Helvetica", "B", Unit::pt(10.0));
                self.pdf.cell_format(
                    Unit::mm(CONTENT_WIDTH_MM),
                    Unit::mm(6.0),
                    &clean_text(title),
                    "",
                    1,
                    "L",
                    false,
                    0,
                    "",
                );
            }
        }
    }

    pub(crate) fn ensure_space(&mut self, height_mm: f64) {
        let y = self.pdf.get_y().to_mm();

        if y + height_mm > A4_HEIGHT_MM - BOTTOM_MARGIN_MM {
            self.pdf.add_page();
        }
    }
}
