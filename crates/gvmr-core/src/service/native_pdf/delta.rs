use fpdf::{Pdf, RGB, Unit};

use crate::domain::report_model::DeltaState;

use super::{constants::CONTENT_WIDTH_MM, document::NativePdfDocument};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLineKind {
    Hunk,
    Added,
    Removed,
    Context,
}

pub fn classify_diff_line(line: &str) -> DiffLineKind {
    if line.starts_with("@@") {
        DiffLineKind::Hunk
    } else if line.starts_with('+') && !line.starts_with("+++") {
        DiffLineKind::Added
    } else if line.starts_with('-') && !line.starts_with("---") {
        DiffLineKind::Removed
    } else {
        DiffLineKind::Context
    }
}

pub(crate) fn diff_line_fill(kind: DiffLineKind) -> RGB {
    match kind {
        DiffLineKind::Hunk => RGB::new(238, 232, 248),
        DiffLineKind::Added => RGB::new(226, 244, 228),
        DiffLineKind::Removed => RGB::new(252, 230, 230),
        DiffLineKind::Context => RGB::new(255, 255, 255),
    }
}

pub fn delta_marker(state: DeltaState) -> &'static str {
    match state {
        DeltaState::Same => "=",
        DeltaState::New => "+",
        DeltaState::Gone => "-",
        DeltaState::Changed => "~",
    }
}

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn write_delta_marker(&mut self, state: DeltaState) {
        self.ensure_space(5.0);
        self.pdf.set_font("Helvetica", "B", Unit::pt(9.0));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.cell_format(
            Unit::mm(6.0),
            Unit::mm(5.0),
            delta_marker(state),
            "",
            0,
            "L",
            false,
            0,
            "",
        );
    }

    pub(crate) fn write_diff_block(&mut self, diff: &str) {
        let line_count = diff.lines().count().max(1);
        if line_count <= 12 {
            self.ensure_space(line_count as f64 * 4.0 + 2.0);
        }
        self.pdf.set_font("Courier", "", Unit::pt(7.5));
        self.pdf.set_text_color(RGB::new(0, 0, 0));

        for line in diff.split('\n') {
            self.write_diff_line(line, classify_diff_line(line));
        }

        self.pdf.set_fill_color(RGB::new(255, 255, 255));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
    }

    fn write_diff_line(&mut self, line: &str, kind: DiffLineKind) {
        self.ensure_space(4.0);
        self.pdf.set_fill_color(diff_line_fill(kind));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(4.0),
            line,
            "1",
            "L",
            true,
        );
    }
}

#[cfg(test)]
#[path = "delta_tests.rs"]
mod delta_tests;
