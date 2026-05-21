use fpdf::{Pdf, RGB, Unit};

use crate::service::{
    native_pdf::target::ReportTargetKind,
    pdf_renderer_helper::{clean_text, count_threat},
};

use super::{constants::CONTENT_WIDTH_MM, document::NativePdfDocument};

#[derive(Debug, Clone)]
struct OverviewRow {
    key: String,
    display: String,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    log: usize,
    is_total: bool,
}

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn write_result_overview(&mut self) {
        self.pdf.add_page();

        let page = self.pdf.page_no();
        self.set_toc_page("1", page);
        self.set_link_here(self.toc_link("1"), page);
        self.write_heading("1 Result Overview", 1);

        let target_header = self.target_kind.overview_column();
        let headers = [target_header, "Critical", "High", "Medium", "Low", "Log"];
        let widths = [55.0, 24.0, 24.0, 24.0, 24.0, 24.0];

        self.pdf.set_font("Helvetica", "B", Unit::pt(8.0));
        self.pdf.set_fill_color(RGB::new(220, 230, 240));
        self.pdf.set_text_color(RGB::new(0, 0, 0));

        for (index, header) in headers.iter().enumerate() {
            self.pdf.cell_format(
                Unit::mm(widths[index]),
                Unit::mm(7.0),
                header,
                "1",
                0,
                "C",
                true,
                0,
                "",
            );
        }

        self.pdf.ln(Unit::negative());
        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));

        for row in self.build_overview_rows() {
            let host_link = if row.is_total {
                0
            } else {
                self.host_links.get(&row.key).copied().unwrap_or(0)
            };

            let cells = [
                row.display,
                row.critical.to_string(),
                row.high.to_string(),
                row.medium.to_string(),
                row.low.to_string(),
                row.log.to_string(),
            ];

            for (index, cell) in cells.iter().enumerate() {
                let is_target_cell = index == 0 && !row.is_total && host_link != 0;

                if is_target_cell {
                    self.pdf.set_text_color(RGB::new(0, 90, 180));
                } else {
                    self.pdf.set_text_color(RGB::new(0, 0, 0));
                }

                self.pdf.cell_format(
                    Unit::mm(widths[index]),
                    Unit::mm(6.0),
                    &clean_text(cell),
                    "1",
                    0,
                    "C",
                    false,
                    if is_target_cell { host_link } else { 0 },
                    "",
                );
            }

            self.pdf.set_text_color(RGB::new(0, 0, 0));
            self.pdf.ln(Unit::negative());
        }

        self.write_filter_summary_text();

        self.write_authentication_table("1.1");
    }

    pub(crate) fn has_authentication_rows(&self) -> bool {
        self.target_kind == ReportTargetKind::Host && !self.report.report.auth_rows().is_empty()
    }

    pub(crate) fn write_authentication_table(&mut self, section_number: &str) {
        if !self.has_authentication_rows() {
            return;
        }

        let rows = self.report.report.auth_rows();

        let page = self.pdf.page_no();
        self.set_toc_page(section_number, page);
        self.set_link_here(self.toc_link(section_number), page);

        self.pdf.ln(Unit::mm(6.0));

        self.write_heading(&format!("{section_number} Host Authentications"), 2);

        let headers = ["Host", "Protocol", "Result", "Port/User"];
        let widths = [80.0, 22.0, 20.0, 60.0];

        self.ensure_space(18.0);

        self.pdf.set_font("Helvetica", "B", Unit::pt(8.0));
        self.pdf.set_fill_color(RGB::new(200, 215, 235));
        self.pdf.set_text_color(RGB::new(0, 0, 0));

        for (index, header) in headers.iter().enumerate() {
            self.pdf.cell_format(
                Unit::mm(widths[index]),
                Unit::mm(7.0),
                header,
                "1",
                0,
                "L",
                true,
                0,
                "",
            );
        }

        self.pdf.ln(Unit::negative());
        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));

        for row in rows {
            self.ensure_space(7.0);

            let cells = [
                clean_text(&row.target),
                row.protocol.to_string(),
                row.result.to_string(),
                clean_text(&row.value),
            ];

            for (index, cell) in cells.iter().enumerate() {
                self.pdf.cell_format(
                    Unit::mm(widths[index]),
                    Unit::mm(6.0),
                    cell,
                    "1",
                    0,
                    "L",
                    false,
                    0,
                    "",
                );
            }

            self.pdf.ln(Unit::negative());
        }

        self.pdf.ln(Unit::mm(4.0));
    }

    fn build_overview_rows(&self) -> Vec<OverviewRow> {
        let grouped = self.group_results_by_target();

        let mut rows = Vec::new();

        let mut total_critical = 0usize;
        let mut total_high = 0usize;
        let mut total_medium = 0usize;
        let mut total_low = 0usize;
        let mut total_log = 0usize;

        for (target, results) in grouped {
            let critical = count_threat(&results, "critical");
            let high = count_threat(&results, "high");
            let medium = count_threat(&results, "medium");
            let low = count_threat(&results, "low");
            let log = count_threat(&results, "log");

            total_critical += critical;
            total_high += high;
            total_medium += medium;
            total_low += low;
            total_log += log;

            let display = self.target_display_name(&target, &results);

            rows.push(OverviewRow {
                key: target,
                display,
                critical,
                high,
                medium,
                low,
                log,
                is_total: false,
            });
        }

        rows.push(OverviewRow {
            key: "Total".to_string(),
            display: "Total".to_string(),
            critical: total_critical,
            high: total_high,
            medium: total_medium,
            low: total_low,
            log: total_log,
            is_total: true,
        });

        rows
    }

    fn write_filter_summary_text(&mut self) {
        let text = self.build_filter_summary_text();

        if text.trim().is_empty() {
            return;
        }

        self.pdf.ln(Unit::mm(8.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(9.0));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(5.0),
            &clean_text(&text),
            "",
            "L",
            false,
        );
    }

    fn build_filter_summary_text(&self) -> String {
        let mut lines = Vec::new();

        match self.filter_keyword_value("autofp").as_deref() {
            Some("1") => lines
                .push("Vendor security updates are trusted, using full CVE matching.".to_string()),
            Some("2") => lines.push(
                "Vendor security updates are trusted, using partial CVE matching.".to_string(),
            ),
            _ => lines.push("Vendor security updates are not trusted.".to_string()),
        }

        match self.filter_keyword_value("apply_overrides").as_deref() {
            Some("1") => lines.push(
                "Overrides are on. When a result has an override, this report uses the threat of the override."
                    .to_string(),
            ),
            _ => lines.push(
                "Overrides are off. Even when a result has an override, this report uses the actual threat of the result."
                    .to_string(),
            ),
        }

        match self.filter_keyword_value("overrides").as_deref() {
            Some("0") => {
                lines.push("Information on overrides is excluded from the report.".to_string())
            }
            _ => lines.push("Information on overrides is included in the report.".to_string()),
        }

        match self.filter_keyword_value("notes").as_deref() {
            Some("0") => lines.push("Notes are excluded from the report.".to_string()),
            _ => lines.push("Notes are included in the report.".to_string()),
        }

        lines.push("This report might not show details of all issues that were found.".to_string());

        if self.filter_keyword_value("result_hosts_only").as_deref() == Some("1") {
            lines.push("It only lists hosts that produced issues.".to_string());
        }

        if let Some(term) = self.report.report.filters.as_ref().and_then(|filters| {
            filters
                .term
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }) {
            lines.push(format!(
                "It shows issues that contain the search phrase \"{term}\"."
            ));
        }

        if let Some(levels) = self.filter_keyword_value("levels") {
            self.append_missing_threat_level_text(&mut lines, &levels);
        }

        match self.filter_keyword_value("min_qod").as_deref() {
            Some("0") => {}
            Some(value) if !value.trim().is_empty() => {
                lines.push(format!(
                    "Only results with a minimum QoD of {value} are shown."
                ));
            }
            _ => {
                lines.push("Only results with a minimum QoD of 70 are shown.".to_string());
            }
        }

        lines.push(self.result_count_summary_text());

        lines.join("\n")
    }

    fn append_missing_threat_level_text(&self, lines: &mut Vec<String>, levels: &str) {
        let levels = levels.trim();

        if levels.is_empty() {
            return;
        }

        let checks = [
            ('c', "Critical"),
            ('h', "High"),
            ('m', "Medium"),
            ('l', "Low"),
            ('g', "Log"),
            ('d', "Debug"),
            ('f', "False Positive"),
        ];

        for (flag, label) in checks {
            if !levels.contains(flag) {
                lines.push(format!(
                    "Issues with the threat level \"{label}\" are not shown."
                ));
            }
        }
    }

    fn result_count_summary_text(&self) -> String {
        let shown_count = self
            .report
            .report
            .results
            .as_ref()
            .map(|results| results.result.len())
            .unwrap_or(0);

        let start = self
            .report
            .report
            .results
            .as_ref()
            .and_then(|results| results.start.as_deref())
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);

        let filtered_count = self
            .report
            .report
            .result_count
            .as_ref()
            .and_then(|count| count.filtered.as_deref())
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(shown_count);

        let full_count = self
            .report
            .report
            .result_count
            .as_ref()
            .and_then(|count| count.full.as_deref())
            .and_then(|value| value.parse::<usize>().ok());

        let last = if shown_count == 0 {
            0
        } else {
            start + shown_count - 1
        };

        let mut text = if shown_count == 0 {
            "This report contains 0 results.".to_string()
        } else if shown_count == filtered_count {
            format!(
                "This report contains all {filtered_count} results selected by the filtering described above."
            )
        } else if shown_count == 1 {
            format!(
                "This report contains result {last} of the {filtered_count} results selected by the filtering above."
            )
        } else {
            format!(
                "This report contains results {start} to {last} of the {filtered_count} results selected by the filtering described above."
            )
        };

        if let Some(full_count) = full_count {
            text.push_str(&format!(
                " Before filtering there were {full_count} results."
            ));
        }

        text
    }

    fn filter_keyword_value(&self, column: &str) -> Option<String> {
        self.report
            .report
            .filters
            .as_ref()?
            .keywords
            .as_ref()?
            .keyword
            .iter()
            .find(|keyword| {
                keyword
                    .column
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|value| value.eq_ignore_ascii_case(column))
            })?
            .value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }
}
