use std::collections::BTreeMap;

use fpdf::{Pdf, RGB, Unit};

use crate::{service::pdf_renderer_helper::clean_text, service::report_view::grouped_threats};

use super::{document::NativePdfDocument, grouping::FindingKey};

#[derive(Debug, Clone)]
pub(crate) struct TocEntry {
    pub(crate) number: String,
    pub(crate) title: String,
    pub(crate) level: usize,
    pub(crate) page: usize,
    pub(crate) link: usize,
}

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn prepare_toc(&mut self, known_pages: Option<&BTreeMap<String, usize>>) {
        self.toc.clear();
        self.host_links.clear();
        self.finding_links.clear();

        let overview_link = self.pdf.add_link();
        self.add_toc_entry("1", "Result Overview", 1, overview_link, known_pages);

        if self.has_authentication_rows() {
            let auth_link = self.pdf.add_link();
            self.add_toc_entry("1.1", "Host Authentications", 2, auth_link, known_pages);
        }

        let results_link = self.pdf.add_link();
        self.add_toc_entry(
            "2",
            self.target.results_section_title(),
            1,
            results_link,
            known_pages,
        );

        let grouped = self.group_results_by_target();

        for (host_index, (host, results)) in grouped.iter().enumerate() {
            let host_number = format!("2.{}", host_index + 1);
            let host_link = self.pdf.add_link();

            self.host_links.insert(host.clone(), host_link);

            let display_host = self.target_display_name(host, results);

            self.add_toc_entry(&host_number, &display_host, 2, host_link, known_pages);

            if self.target.is_grouped_by_threat() {
                for (threat_index, threat) in grouped_threats(results).iter().enumerate() {
                    let finding_number = format!("{host_number}.{}", threat_index + 1);
                    let finding_link = self.pdf.add_link();

                    let key = FindingKey {
                        host: host.clone(),
                        index: threat_index,
                    };

                    self.finding_links.insert(key, finding_link);

                    self.add_toc_entry(&finding_number, threat, 3, finding_link, known_pages);
                }
            } else {
                for (result_index, result) in results.iter().enumerate() {
                    let finding_number = format!("{host_number}.{}", result_index + 1);
                    let finding_link = self.pdf.add_link();

                    let key = FindingKey {
                        host: host.clone(),
                        index: result_index,
                    };

                    self.finding_links.insert(key, finding_link);

                    let title = self.target.finding_title(result);

                    self.add_toc_entry(&finding_number, &title, 3, finding_link, known_pages);
                }
            }
        }
    }

    pub(crate) fn add_toc_entry(
        &mut self,
        number: &str,
        title: &str,
        level: usize,
        link: usize,
        known_pages: Option<&BTreeMap<String, usize>>,
    ) {
        let page = known_pages
            .and_then(|pages| pages.get(number).copied())
            .unwrap_or(0);

        self.toc.push(TocEntry {
            number: number.to_string(),
            title: title.to_string(),
            level,
            page,
            link,
        });
    }

    pub(crate) fn toc_pages(&self) -> BTreeMap<String, usize> {
        self.toc
            .iter()
            .map(|entry| (entry.number.clone(), entry.page))
            .collect()
    }

    pub(crate) fn set_toc_page(&mut self, number: &str, page: usize) {
        if let Some(entry) = self.toc.iter_mut().find(|entry| entry.number == number) {
            entry.page = page;
        }
    }

    pub(crate) fn toc_link(&self, number: &str) -> usize {
        self.toc
            .iter()
            .find(|entry| entry.number == number)
            .map(|entry| entry.link)
            .unwrap_or(0)
    }

    pub(crate) fn write_toc_entry(&mut self, entry: &TocEntry) {
        let row_h = 5.3;

        self.ensure_space(row_h + 1.0);

        let number_x = 14.0;
        let title_x = 32.0;
        let dots_x = 95.0;
        let page_x = 184.0;

        let number_w = title_x - number_x - 2.0;
        let title_w = dots_x - title_x - 4.0;
        let dots_w = page_x - dots_x - 6.0;
        let page_w = 9.0;

        let title_font_size = if entry.level >= 3 { 8.0 } else { 8.5 };
        let dots_font_size = 8.5;

        let y = self.pdf.get_y();

        self.pdf
            .set_font("Helvetica", "", Unit::pt(title_font_size));

        self.pdf.set_text_color(RGB::new(0, 90, 180));

        self.pdf.set_xy(Unit::mm(number_x), y);
        self.pdf.cell_format(
            Unit::mm(number_w),
            Unit::mm(row_h),
            &entry.number,
            "",
            0,
            "L",
            false,
            entry.link,
            "",
        );

        let title = clean_text(&entry.title);
        let title = shorten_toc_title_for_width(&title, title_w, title_font_size);

        self.pdf.set_xy(Unit::mm(title_x), y);
        self.pdf.cell_format(
            Unit::mm(title_w),
            Unit::mm(row_h),
            &title,
            "",
            0,
            "L",
            false,
            entry.link,
            "",
        );

        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.set_font("Helvetica", "", Unit::pt(dots_font_size));

        self.pdf.set_xy(Unit::mm(dots_x), y);
        self.pdf.cell_format(
            Unit::mm(dots_w),
            Unit::mm(row_h),
            &toc_leader_dots(),
            "",
            0,
            "R",
            false,
            0,
            "",
        );

        self.pdf
            .set_font("Helvetica", "", Unit::pt(title_font_size));

        self.pdf.set_xy(Unit::mm(page_x), y);
        self.pdf.cell_format(
            Unit::mm(page_w),
            Unit::mm(row_h),
            &entry.page.to_string(),
            "",
            0,
            "R",
            false,
            0,
            "",
        );

        self.pdf.set_y(y + Unit::mm(row_h));
    }
}

fn toc_leader_dots() -> String {
    ".".repeat(100)
}

fn shorten_toc_title_for_width(value: &str, max_width_mm: f64, font_size_pt: f64) -> String {
    if estimated_text_width_mm(value, font_size_pt) <= max_width_mm {
        return value.to_string();
    }

    let ellipsis = "…";
    let mut result = String::new();

    for ch in value.chars() {
        let candidate = format!("{result}{ch}{ellipsis}");

        if estimated_text_width_mm(&candidate, font_size_pt) > max_width_mm {
            break;
        }

        result.push(ch);
    }

    if result.is_empty() {
        ellipsis.to_string()
    } else {
        format!("{result}{ellipsis}")
    }
}

fn estimated_text_width_mm(value: &str, font_size_pt: f64) -> f64 {
    let average_char_width_mm = font_size_pt * 0.352_778 * 0.48;

    value.chars().count() as f64 * average_char_width_mm
}

#[cfg(test)]
#[path = "toc_tests.rs"]
mod toc_tests;
