use fpdf::{Pdf, RGB, Unit};

use crate::{
    domain::report_model::ReportResult,
    service::pdf_renderer_helper::{clean_text, severity_color, truncate_text},
    service::report_view::{
        detection_method, result_affected, result_impact, result_insight, result_name, result_qod,
        result_references, result_severity, result_solution, result_summary, result_threat,
    },
};

use super::{
    constants::{A4_HEIGHT_MM, BOTTOM_MARGIN_MM, CONTENT_WIDTH_MM, MAX_FIELD_CHARS},
    document::NativePdfDocument,
};

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn write_finding_card(&mut self, title: &str, result: &ReportResult) {
        self.ensure_space(45.0);

        let (red, green, blue) = severity_color(result_threat(result));

        self.pdf.set_fill_color(RGB::new(red, green, blue));
        self.pdf.set_text_color(RGB::new(255, 255, 255));
        self.pdf.set_font("Helvetica", "B", Unit::pt(9.0));

        let header = if result_severity(result).is_empty() {
            clean_text(title)
        } else {
            format!(
                "{}    (CVSS: {})",
                clean_text(title),
                result_severity(result)
            )
        };

        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(7.0),
            &header,
            "1",
            1,
            "L",
            true,
            0,
            "",
        );

        self.pdf.set_text_color(RGB::new(255, 255, 255));
        self.pdf.set_font("Helvetica", "B", Unit::pt(9.0));

        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(7.0),
            &format!("NVT: {}", clean_text(result_name(result))),
            "1",
            1,
            "L",
            true,
            0,
            "",
        );

        self.pdf.set_text_color(RGB::new(0, 0, 0));

        self.write_box_field("Summary", result_summary(result));

        if !result_qod(result).is_empty() {
            self.write_box_field(
                "Quality of Detection (QoD)",
                Some(format!("{}%", result_qod(result))),
            );
        }

        self.write_box_field("Vulnerability Detection Result", result.description.clone());

        self.write_box_field("Impact", result_impact(result));
        self.write_box_field("Solution", result_solution(result));
        self.write_box_field("Affected Software/OS", result_affected(result));
        self.write_box_field("Vulnerability Insight", result_insight(result));
        self.write_box_field("Vulnerability Detection Method", detection_method(result));

        let refs = result_references(result);
        if !refs.is_empty() {
            self.write_box_field("References", Some(refs.join("\n")));
        }

        self.pdf.ln(Unit::mm(6.0));
    }

    pub(crate) fn write_box_field(&mut self, title: &str, value: Option<String>) {
        let Some(value) = value else {
            return;
        };

        let value = truncate_text(&clean_text(value.trim()), MAX_FIELD_CHARS);

        if value.trim().is_empty() {
            return;
        }

        self.write_paginated_box_field(title, &value);
    }

    fn write_paginated_box_field(&mut self, title: &str, value: &str) {
        let title_h = 5.0;
        let line_h = 4.5;
        let top_pad = 1.5;
        let left_pad = 2.0;
        let bottom_pad = 2.0;
        let chars_per_line = 95;

        let lines = box_field_lines(title, value, chars_per_line);

        if lines.is_empty() {
            return;
        }

        let mut line_index = 0usize;
        let mut continued = false;

        while line_index < lines.len() {
            self.ensure_space(title_h + line_h + top_pad + bottom_pad + 2.0);

            let (x, y) = self.pdf.get_xy();
            let available_h = A4_HEIGHT_MM - BOTTOM_MARGIN_MM - y.to_mm();

            let header_h = title_h + top_pad;
            let usable_for_lines = available_h - header_h - bottom_pad;

            if usable_for_lines < line_h {
                self.pdf.add_page();
                continue;
            }

            let max_lines_on_page = (usable_for_lines / line_h).floor().max(1.0) as usize;
            let remaining_lines = lines.len() - line_index;
            let lines_on_page = remaining_lines.min(max_lines_on_page);

            let segment_h = header_h + (lines_on_page as f64 * line_h) + bottom_pad;

            self.pdf
                .rect(x, y, Unit::mm(CONTENT_WIDTH_MM), Unit::mm(segment_h), "D");

            self.pdf
                .set_xy(x + Unit::mm(left_pad), y + Unit::mm(top_pad));
            self.pdf.set_font("Helvetica", "B", Unit::pt(8.5));

            let title_text = if continued {
                format!("{title} (continued)")
            } else {
                title.to_string()
            };

            self.pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM - (left_pad * 2.0)),
                Unit::mm(title_h),
                &title_text,
                "",
                1,
                "L",
                false,
                0,
                "",
            );

            self.pdf.set_font("Helvetica", "", Unit::pt(8.5));

            let mut current_y = y + Unit::mm(header_h);

            for line in &lines[line_index..line_index + lines_on_page] {
                self.pdf.set_xy(x + Unit::mm(left_pad), current_y);

                match line {
                    BoxFieldLine::Text(text) => {
                        self.write_text_line(text, CONTENT_WIDTH_MM - (left_pad * 2.0), line_h);
                    }
                    BoxFieldLine::Url { text, target } => {
                        self.write_url_line(
                            text,
                            target,
                            CONTENT_WIDTH_MM - (left_pad * 2.0),
                            line_h,
                        );
                    }
                }

                current_y += Unit::mm(line_h);
            }

            self.pdf.set_xy(x, y + Unit::mm(segment_h));

            line_index += lines_on_page;
            continued = true;

            if line_index < lines.len() {
                self.pdf.add_page();
            }
        }
    }

    fn write_text_line(&mut self, line: &str, width_mm: f64, line_h: f64) {
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.cell_format(
            Unit::mm(width_mm),
            Unit::mm(line_h),
            line,
            "",
            1,
            "L",
            false,
            0,
            "",
        );
    }

    fn write_url_line(&mut self, line: &str, target: &str, width_mm: f64, line_h: f64) {
        self.pdf.set_text_color(RGB::new(0, 90, 180));
        self.pdf.cell_format(
            Unit::mm(width_mm),
            Unit::mm(line_h),
            line,
            "",
            1,
            "L",
            false,
            0,
            target,
        );
        self.pdf.set_text_color(RGB::new(0, 0, 0));
    }
}

fn wrap_single_line(line: &str, max_chars: usize) -> Vec<String> {
    if line.chars().count() <= max_chars {
        return vec![line.to_string()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in line.split_whitespace() {
        let word_len = word.chars().count();
        let current_len = current.chars().count();

        if word_len > max_chars {
            if !current.is_empty() {
                lines.push(current);
                current = String::new();
            }

            lines.extend(split_long_word(word, max_chars));
            continue;
        }

        let next_len = if current.is_empty() {
            word_len
        } else {
            current_len + 1 + word_len
        };

        if next_len > max_chars {
            lines.push(current);
            current = word.to_string();
        } else {
            if !current.is_empty() {
                current.push(' ');
            }

            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
}

fn split_long_word(word: &str, max_chars: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();

    for ch in word.chars() {
        if current.chars().count() >= max_chars {
            chunks.push(current);
            current = String::new();
        }

        current.push(ch);
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

fn reference_url(value: &str) -> Option<&str> {
    let value = value.trim();

    let value = value
        .strip_prefix("url:")
        .or_else(|| value.strip_prefix("URL:"))
        .map(str::trim)
        .unwrap_or(value);

    if value.starts_with("http://") || value.starts_with("https://") {
        Some(value)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BoxFieldLine {
    Text(String),
    Url { text: String, target: String },
}

fn box_field_lines(title: &str, value: &str, max_chars: usize) -> Vec<BoxFieldLine> {
    let is_references = title.eq_ignore_ascii_case("References");
    let mut output = Vec::new();

    for raw_line in value.lines() {
        let line = raw_line.trim();

        if line.is_empty() {
            output.push(BoxFieldLine::Text(String::new()));
            continue;
        }

        if is_references && let Some(url) = reference_url(line) {
            for chunk in wrap_single_line(url, max_chars) {
                output.push(BoxFieldLine::Url {
                    text: chunk,
                    target: url.to_string(),
                });
            }

            continue;
        }

        for chunk in wrap_single_line(line, max_chars) {
            output.push(BoxFieldLine::Text(chunk));
        }
    }

    output
}

#[cfg(test)]
#[path = "findings_tests.rs"]
mod findings_tests;
