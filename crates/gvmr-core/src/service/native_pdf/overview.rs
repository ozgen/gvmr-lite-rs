use fpdf::{Pdf, RGB, Unit};

use crate::{
    service::pdf_renderer_helper::clean_text,
    service::report_view::{ReportTargetKind, count_threat},
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

        let target_width = 82.0;
        let metric_width = (CONTENT_WIDTH_MM - target_width) / 5.0;

        let widths = [
            target_width,
            metric_width,
            metric_width,
            metric_width,
            metric_width,
            metric_width,
        ];

        let target_header = self.target.overview_column();
        let headers = [target_header, "Critical", "High", "Medium", "Low", "Log"];

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

            let has_multiple_lines = row.display.lines().count() > 1;
            let row_height = if has_multiple_lines { 10.0 } else { 6.0 };

            self.ensure_space(row_height);

            let (start_x, start_y) = self.pdf.get_xy();

            /*
             * Draw the target cell manually because cell_format does not
             * support a two-line value within one bordered table cell.
             */
            self.pdf.rect(
                start_x,
                start_y,
                Unit::mm(widths[0]),
                Unit::mm(row_height),
                "D",
            );

            let is_target_link = !row.is_total && host_link != 0;

            if is_target_link {
                self.pdf.set_text_color(RGB::new(0, 90, 180));
            } else {
                self.pdf.set_text_color(RGB::new(0, 0, 0));
            }

            let display_lines = row.display.lines().collect::<Vec<_>>();
            let line_height = 4.0;

            let first_line_y = start_y + Unit::mm(1.0);

            if let Some(first_line) = display_lines.first() {
                self.pdf.set_xy(start_x + Unit::mm(2.0), first_line_y);

                self.pdf.cell_format(
                    Unit::mm(widths[0] - 4.0),
                    Unit::mm(line_height),
                    &clean_text(first_line),
                    "",
                    0,
                    "L",
                    false,
                    if is_target_link { host_link } else { 0 },
                    "",
                );
            }

            if let Some(second_line) = display_lines.get(1) {
                self.pdf
                    .set_xy(start_x + Unit::mm(2.0), start_y + Unit::mm(5.0));

                self.pdf.cell_format(
                    Unit::mm(widths[0] - 4.0),
                    Unit::mm(line_height),
                    &clean_text(second_line),
                    "",
                    0,
                    "L",
                    false,
                    if is_target_link { host_link } else { 0 },
                    "",
                );
            }

            self.pdf.set_text_color(RGB::new(0, 0, 0));
            self.pdf.set_xy(start_x + Unit::mm(widths[0]), start_y);

            let values = [
                row.critical.to_string(),
                row.high.to_string(),
                row.medium.to_string(),
                row.low.to_string(),
                row.log.to_string(),
            ];

            for (index, value) in values.iter().enumerate() {
                self.pdf.cell_format(
                    Unit::mm(widths[index + 1]),
                    Unit::mm(row_height),
                    value,
                    "1",
                    0,
                    "C",
                    false,
                    0,
                    "",
                );
            }

            self.pdf.set_xy(start_x, start_y + Unit::mm(row_height));
        }

        self.pdf.set_text_color(RGB::new(0, 0, 0));

        self.write_filter_summary_text();
        self.write_authentication_table("1.1");
    }

    pub(crate) fn has_authentication_rows(&self) -> bool {
        self.target == ReportTargetKind::Host && !self.report.report.auth_rows().is_empty()
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
            let display = self.overview_target_display(&display);

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

    /*
     * Convert:
     *
     *   IP (agent ID)
     *
     * into:
     *
     *   IP
     *   (agent ID)
     *
     * only for the overview table.
     */
    fn overview_target_display(&self, display: &str) -> String {
        if self.target != ReportTargetKind::Agent {
            return display.to_string();
        }

        match display.rsplit_once(" (") {
            Some((address, agent_id)) => {
                format!("{address}\n({agent_id}")
            }
            None => display.to_string(),
        }
    }

    fn write_filter_summary_text(&mut self) {
        let text = self.view.filter_summary_text();

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
}

#[cfg(test)]
#[path = "overview_tests.rs"]
mod overview_tests;
