use fpdf::{Pdf, RGB, Unit};

use crate::{
    domain::report_model::{ComplianceStatus, DeltaState, FullFiltered, ReportResult},
    service::{
        pdf_renderer_helper::clean_text,
        report_view::{detection_method, result_name, result_references},
        report_view::{filter_keyword_value, result_port, result_qod, result_summary},
    },
};

use super::{
    constants::CONTENT_WIDTH_MM, delta::delta_marker, document::NativePdfDocument,
    grouping::FindingKey,
};

const COMPLIANCE_BODY_FONT_PT: f64 = 8.0;
const COMPLIANCE_SMALL_FONT_PT: f64 = 7.0;
const COMPLIANCE_LINE_HEIGHT_MM: f64 = 4.5;
const COMPLIANCE_SECTION_GAP_MM: f64 = 3.0;
const COMPLIANCE_RESULT_GAP_MM: f64 = 5.0;
const COMPLIANCE_LABEL_WIDTH_MM: f64 = 34.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComplianceDisplayStatus {
    Yes,
    No,
    Incomplete,
    Log,
    Undefined,
}

impl<'a> NativePdfDocument<'a> {
    fn compliance_log_count(&self) -> usize {
        self.report
            .report
            .results
            .as_ref()
            .map(|results| {
                results
                    .result
                    .iter()
                    .filter(|result| {
                        compliance_display_status(result) == ComplianceDisplayStatus::Log
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn host_compliance_log_count(&self, host: &str) -> usize {
        self.report
            .report
            .results
            .as_ref()
            .map(|results| {
                results
                    .result
                    .iter()
                    .filter(|result| {
                        result.target_address() == Some(host)
                            && compliance_display_status(result) == ComplianceDisplayStatus::Log
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    pub(crate) fn write_compliance_overview(&mut self) {
        self.pdf.add_page();

        let page = self.pdf.page_no();
        self.set_toc_page("1", page);
        self.set_link_here(self.toc_link("1"), page);
        self.write_heading("1 Compliance Overview", 1);

        self.write_compliance_metadata();
        self.write_compliance_totals();
        self.write_host_compliance_summary();
        self.write_compliance_notes();

        if self.report.report.is_delta_report() {
            let results = self
                .report
                .report
                .results
                .as_ref()
                .map(|results| results.result.as_slice())
                .unwrap_or(&[]);
            self.write_delta_summary(&delta_state_counts(results));
        }
    }

    fn write_compliance_metadata(&mut self) {
        let report = &self.report.report;
        let mut rows = Vec::new();

        if let Some(name) = self.report.name.as_deref().and_then(non_empty_text) {
            rows.push(("Report".to_string(), clean_text(name)));
        }
        if let Some(task) = report
            .task
            .as_ref()
            .and_then(|task| task.name.as_deref())
            .and_then(non_empty_text)
        {
            rows.push(("Task".to_string(), clean_text(task)));
        }
        if let Some(target) = report
            .task
            .as_ref()
            .and_then(|task| task.target.as_ref())
            .and_then(|target| target.name.as_deref())
            .and_then(non_empty_text)
        {
            rows.push(("Target".to_string(), clean_text(target)));
        }
        if let Some(hosts) = report
            .hosts
            .as_ref()
            .and_then(|hosts| hosts.count.as_deref())
        {
            rows.push(("Hosts".to_string(), clean_text(hosts)));
        }
        if let Some(start) = report.scan_start.as_deref().and_then(non_empty_text) {
            rows.push(("Scan Start".to_string(), clean_text(start)));
        }
        if let Some(end) = report.scan_end.as_deref().and_then(non_empty_text) {
            rows.push(("Scan End".to_string(), clean_text(end)));
        }

        if rows.is_empty() {
            return;
        }

        self.write_label_value_rows(&rows);
    }

    fn write_label_value_rows(&mut self, rows: &[(String, String)]) {
        self.ensure_space(rows.len() as f64 * 5.0 + 3.0);
        for (label, value) in rows {
            self.pdf.set_font("Helvetica", "B", Unit::pt(8.0));
            self.pdf.set_text_color(RGB::new(0, 0, 0));
            self.pdf.cell_format(
                Unit::mm(45.0),
                Unit::mm(5.0),
                label,
                "",
                0,
                "L",
                false,
                0,
                "",
            );
            self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
            self.pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM - 45.0),
                Unit::mm(5.0),
                value,
                "",
                1,
                "L",
                false,
                0,
                "",
            );
        }
        self.pdf.ln(Unit::mm(COMPLIANCE_SECTION_GAP_MM));
    }

    fn write_compliance_totals(&mut self) {
        let count = self.report.report.compliance_count.as_ref();
        let total = count.and_then(|value| value.filtered.as_deref().or(value.full.as_deref()));
        let yes = count
            .and_then(|value| value.yes.as_ref())
            .and_then(filtered_or_full);
        let no = count
            .and_then(|value| value.no.as_ref())
            .and_then(filtered_or_full);
        let incomplete = count
            .and_then(|value| value.incomplete.as_ref())
            .and_then(filtered_or_full);
        let undefined = count
            .and_then(|value| value.undefined.as_ref())
            .and_then(filtered_or_full);
        let log = self.compliance_log_count();
        let policy_total = [yes, no, incomplete, undefined]
            .into_iter()
            .filter_map(|value| value.and_then(parse_count))
            .sum::<usize>();
        let displayed_total = total
            .and_then(parse_count)
            .map(|value| value + log)
            .or_else(|| (policy_total + log).to_string().parse().ok());

        let compliance = match (yes.and_then(parse_count), Some(policy_total)) {
            (Some(yes), Some(policy_total)) => compliance_percentage(yes, policy_total)
                .map(|value| format!("{value:.2}%"))
                .or_else(|| {
                    self.report
                        .report
                        .compliance
                        .as_ref()
                        .and_then(compliance_value)
                }),
            _ => self
                .report
                .report
                .compliance
                .as_ref()
                .and_then(compliance_value),
        };

        let headers = [
            "Result Count",
            "Yes",
            "No",
            "Incomplete",
            "Log",
            "Undefined",
            "Compliance",
        ];
        let displayed_total = displayed_total.map(|value| value.to_string());
        let log_value = log.to_string();
        let values = [
            displayed_total.as_deref(),
            yes,
            no,
            incomplete,
            Some(log_value.as_str()),
            undefined,
            compliance.as_deref(),
        ];
        let widths = [25.0; 7];

        self.ensure_space(13.0);
        self.pdf
            .set_font("Helvetica", "B", Unit::pt(COMPLIANCE_SMALL_FONT_PT));
        self.pdf.set_fill_color(RGB::new(220, 230, 240));
        for (index, header) in headers.iter().enumerate() {
            self.pdf.cell_format(
                Unit::mm(widths[index]),
                Unit::mm(6.5),
                header,
                "1",
                if index == headers.len() - 1 { 1 } else { 0 },
                "C",
                true,
                0,
                "",
            );
        }
        self.pdf
            .set_font("Helvetica", "", Unit::pt(COMPLIANCE_SMALL_FONT_PT));
        self.pdf.set_fill_color(RGB::new(255, 255, 255));
        for (index, value) in values.iter().enumerate() {
            self.pdf.cell_format(
                Unit::mm(widths[index]),
                Unit::mm(6.0),
                value.unwrap_or(""),
                "1",
                if index == values.len() - 1 { 1 } else { 0 },
                "C",
                false,
                0,
                "",
            );
        }
        self.pdf.ln(Unit::mm(COMPLIANCE_SECTION_GAP_MM));
    }

    fn write_host_compliance_summary(&mut self) {
        let mut rows: Vec<(String, [String; 5])> = Vec::new();
        for host in &self.report.report.hosts_detail {
            let Some(count) = host.compliance_count.as_ref() else {
                continue;
            };

            rows.push((
                host.display_name().unwrap_or_else(|| "-".to_string()),
                [
                    count
                        .yes
                        .as_ref()
                        .and_then(|value| value.page.clone())
                        .unwrap_or_default(),
                    count
                        .no
                        .as_ref()
                        .and_then(|value| value.page.clone())
                        .unwrap_or_default(),
                    count
                        .incomplete
                        .as_ref()
                        .and_then(|value| value.page.clone())
                        .unwrap_or_default(),
                    self.host_compliance_log_count(host.address().unwrap_or(""))
                        .to_string(),
                    count
                        .undefined
                        .as_ref()
                        .and_then(|value| value.page.clone())
                        .unwrap_or_default(),
                ],
            ));
        }

        self.write_heading("Host Summary", 2);
        let widths = [58.0, 24.0, 24.0, 24.0, 24.0, 24.0];
        self.ensure_space(13.0 + (rows.len() + 1) as f64 * 6.0);
        self.pdf
            .set_font("Helvetica", "B", Unit::pt(COMPLIANCE_SMALL_FONT_PT));
        self.pdf.set_fill_color(RGB::new(220, 230, 240));
        for (index, header) in ["Host", "Yes", "No", "Incomplete", "Log", "Undefined"]
            .iter()
            .enumerate()
        {
            self.pdf.cell_format(
                Unit::mm(widths[index]),
                Unit::mm(6.5),
                header,
                "1",
                if index == widths.len() - 1 { 1 } else { 0 },
                "C",
                true,
                0,
                "",
            );
        }

        let total = if let Some(count) = self.report.report.compliance_count.as_ref() {
            [
                count
                    .yes
                    .as_ref()
                    .and_then(filtered_or_full)
                    .unwrap_or("")
                    .to_string(),
                count
                    .no
                    .as_ref()
                    .and_then(filtered_or_full)
                    .unwrap_or("")
                    .to_string(),
                count
                    .incomplete
                    .as_ref()
                    .and_then(filtered_or_full)
                    .unwrap_or("")
                    .to_string(),
                self.compliance_log_count().to_string(),
                count
                    .undefined
                    .as_ref()
                    .and_then(filtered_or_full)
                    .unwrap_or("")
                    .to_string(),
            ]
        } else {
            [0, 1, 2, 3, 4].map(|index| sum_host_values(&rows, index))
        };

        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
        self.pdf.set_fill_color(RGB::new(255, 255, 255));
        for (host, values) in rows
            .iter()
            .chain(std::iter::once(&("Total".to_string(), total)))
        {
            self.ensure_space(6.0);
            self.pdf.cell_format(
                Unit::mm(widths[0]),
                Unit::mm(6.0),
                host,
                "1",
                0,
                "L",
                false,
                0,
                "",
            );
            for (index, value) in values.iter().enumerate() {
                self.pdf.cell_format(
                    Unit::mm(widths[index + 1]),
                    Unit::mm(6.0),
                    value,
                    "1",
                    if index == values.len() - 1 { 1 } else { 0 },
                    "C",
                    false,
                    0,
                    "",
                );
            }
        }
        self.pdf.ln(Unit::mm(5.0));
    }

    fn write_compliance_notes(&mut self) {
        self.write_compliance_note(
            "Compliance status values are grouped as Yes, No, Incomplete, Log, and Undefined.",
        );

        let Some(count) = self.report.report.compliance_count.as_ref() else {
            return;
        };
        let full = count.full.as_deref().and_then(parse_count);
        let filtered = count.filtered.as_deref().and_then(parse_count);

        if let (Some(full), Some(filtered)) = (full, filtered)
            && full != filtered
        {
            self.write_compliance_note(
                "This report might not show details of all compliance results that were found.",
            );
            self.write_compliance_note(&format!(
                    "This report contains {filtered} compliance results selected by the filtering described above. Before filtering there were {full} compliance results."
                ));
        }
        if let Some(qod) = filter_keyword_value(&self.report.report, "min_qod")
            .filter(|value| value != "0" && !value.trim().is_empty())
        {
            self.write_compliance_note(&format!(
                "Only results with a minimum QoD of {qod} are shown."
            ));
        }
    }

    fn write_compliance_note(&mut self, text: &str) {
        self.ensure_space(10.0);
        self.pdf.ln(Unit::mm(2.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(4.5),
            text,
            "",
            "L",
            false,
        );
    }

    fn write_compliance_table(&mut self, rows: &[(&str, &str)]) {
        let label_width = 110.0;
        let value_width = CONTENT_WIDTH_MM - label_width;

        self.ensure_space(13.0 + rows.len() as f64 * 6.0);
        self.pdf
            .set_font("Helvetica", "B", Unit::pt(COMPLIANCE_BODY_FONT_PT));
        self.pdf.set_fill_color(RGB::new(220, 230, 240));
        self.pdf.set_text_color(RGB::new(0, 0, 0));

        self.pdf.cell_format(
            Unit::mm(label_width),
            Unit::mm(6.5),
            "Metric",
            "1",
            0,
            "L",
            true,
            0,
            "",
        );
        self.pdf.cell_format(
            Unit::mm(value_width),
            Unit::mm(7.0),
            "Value",
            "1",
            1,
            "L",
            true,
            0,
            "",
        );

        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
        self.pdf.set_fill_color(RGB::new(255, 255, 255));

        for (label, value) in rows {
            self.ensure_space(6.0);
            self.pdf.cell_format(
                Unit::mm(label_width),
                Unit::mm(6.0),
                label,
                "1",
                0,
                "L",
                false,
                0,
                "",
            );
            self.pdf.cell_format(
                Unit::mm(value_width),
                Unit::mm(6.0),
                value,
                "1",
                1,
                "L",
                false,
                0,
                "",
            );
        }

        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.set_fill_color(RGB::new(255, 255, 255));
    }

    fn write_delta_summary(&mut self, counts: &DeltaStateCounts) {
        self.write_heading("Delta Summary", 3);

        let values = [
            counts.changed.to_string(),
            counts.new.to_string(),
            counts.gone.to_string(),
            counts.same.to_string(),
        ];
        let rows = [
            ("Changed", values[0].as_str()),
            ("New", values[1].as_str()),
            ("Gone", values[2].as_str()),
            ("Same", values[3].as_str()),
        ];

        self.write_compliance_table(&rows);
    }

    pub(crate) fn write_compliance_results_per_host(&mut self) {
        let grouped = self.group_results_by_target();

        if grouped.is_empty() {
            return;
        }

        self.pdf.add_page();

        let page = self.pdf.page_no();
        self.set_toc_page("2", page);
        self.set_link_here(self.toc_link("2"), page);
        self.write_heading("2 Results per Host", 1);

        for (target_index, (target, results)) in grouped.iter().enumerate() {
            let target_number = format!("2.{}", target_index + 1);
            let page = self.pdf.page_no();
            self.set_toc_page(&target_number, page);

            if let Some(link) = self.host_links.get(target).copied() {
                self.set_link_here(link, page);
            }

            let display_target = self.target_display_name(target, results);
            self.write_heading(&format!("{target_number} {display_target}"), 2);
            self.write_target_metadata(results);
            self.write_target_scan_times(target, results);
            let sorted_results = sort_compliance_results(results);
            self.write_compliance_result_table(target, &sorted_results);

            for (result_index, result) in sorted_results.iter().enumerate() {
                let finding_number = format!("{target_number}.{}", result_index + 1);
                let page = self.pdf.page_no();
                self.set_toc_page(&finding_number, page);

                let key = FindingKey {
                    host: target.to_string(),
                    index: result_index,
                };

                if let Some(link) = self.finding_links.get(&key).copied() {
                    self.set_link_here(link, page);
                }

                let title = compliance_result_heading(&finding_number, result);
                if self.report.report.is_delta_report() {
                    self.write_delta_compliance_result(&title, result);
                } else {
                    self.write_compliance_result_card(&title, result);
                }
                self.write_return_to_host_link(target);
                self.pdf.ln(Unit::mm(COMPLIANCE_RESULT_GAP_MM));
            }
        }
    }

    fn write_compliance_result_table(&mut self, target: &str, results: &[ReportResult]) {
        let widths = [45.0, 95.0, CONTENT_WIDTH_MM - 140.0];
        let mut current_page = self.pdf.page_no();

        self.write_compliance_result_header(&widths);

        for (result_index, result) in results.iter().enumerate() {
            let service = clean_text(result_port(result));
            let nvt = result
                .name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(clean_text)
                .unwrap_or_else(|| "-".to_string());
            let nvt = if let Some(state) = result.delta.as_ref().and_then(|delta| delta.state()) {
                format!("{} {}", delta_marker(state), nvt)
            } else {
                nvt
            };
            let nvt = wrap_nvt_name(&nvt, 48);
            let compliance = compliance_display(result);
            let row_height = (nvt.lines().count().max(1) as f64 * 4.5).max(6.0);
            let link = self
                .finding_links
                .get(&FindingKey {
                    host: target.to_string(),
                    index: result_index,
                })
                .copied()
                .unwrap_or(0);

            self.ensure_space(row_height);
            if self.pdf.page_no() != current_page {
                current_page = self.pdf.page_no();
                self.write_compliance_result_header(&widths);
            }

            let (start_x, start_y) = self.pdf.get_xy();
            let cell_text_y = start_y + Unit::mm(1.0);

            let mut cell_x = start_x;
            for width in widths {
                self.pdf
                    .rect(cell_x, start_y, Unit::mm(width), Unit::mm(row_height), "D");
                cell_x += Unit::mm(width);
            }

            self.pdf.set_xy(start_x + Unit::mm(2.0), cell_text_y);
            self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
            self.pdf.cell_format(
                Unit::mm(widths[0] - 4.0),
                Unit::mm(4.5),
                &service,
                "",
                0,
                "L",
                false,
                link,
                "",
            );

            self.pdf
                .set_xy(start_x + Unit::mm(widths[0] + 2.0), cell_text_y);
            self.pdf.multi_cell(
                Unit::mm(widths[1] - 4.0),
                Unit::mm(4.5),
                &nvt,
                "",
                "L",
                false,
            );

            self.pdf
                .set_xy(start_x + Unit::mm(widths[0] + widths[1] + 2.0), cell_text_y);
            let (compliance_fill, _) = compliance_colors(result);
            self.pdf.set_fill_color(compliance_fill);
            self.pdf.cell_format(
                Unit::mm(widths[2] - 4.0),
                Unit::mm(4.5),
                &compliance,
                "",
                0,
                "L",
                true,
                link,
                "",
            );
            self.pdf.set_fill_color(RGB::new(255, 255, 255));

            self.pdf.set_xy(start_x, start_y + Unit::mm(row_height));
        }

        self.pdf.set_text_color(RGB::new(0, 0, 0));
    }

    fn write_compliance_result_header(&mut self, widths: &[f64; 3]) {
        self.ensure_space(7.0);
        self.pdf.set_font("Helvetica", "B", Unit::pt(8.0));
        self.pdf.set_fill_color(RGB::new(220, 230, 240));
        self.pdf.set_text_color(RGB::new(0, 0, 0));

        for (index, header) in ["Service (Port)", "NVT", "Compliance"].iter().enumerate() {
            self.pdf.cell_format(
                Unit::mm(widths[index]),
                Unit::mm(7.0),
                header,
                "1",
                if index == 2 { 1 } else { 0 },
                "L",
                true,
                0,
                "",
            );
        }

        self.pdf.set_fill_color(RGB::new(255, 255, 255));
        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));
    }

    fn write_compliance_result_card(&mut self, title: &str, result: &ReportResult) {
        self.ensure_space(24.0);
        self.write_compliance_result_heading(title);
        self.write_compliance_result_card_body(result);
    }

    fn write_compliance_result_card_body(&mut self, result: &ReportResult) {
        self.write_compliance_status(result);

        if let Some(name) = non_empty_text(result_name(result)) {
            self.write_compliance_nvt_header(name, result);
        }
        let details = result.compliance_details();
        if let Some(summary) = result_summary(result) {
            let is_description_fallback =
                result.description.as_deref().map(str::trim) == Some(summary.trim());
            if !is_description_fallback {
                self.write_compliance_text_section("Summary", &summary);
            }
        }

        let qod = result_qod(result);
        if !qod.is_empty() {
            self.write_compliance_text_section("Quality of Detection (QoD)", &format!("{qod}%"));
        }

        if let Some(details) = details {
            let actual_value = non_empty(details.actual_value.as_deref());
            let set_point = non_empty(details.set_point.as_deref());
            let compliant = result
                .compliance_status()
                .map(compliance_status_text)
                .map(str::to_string)
                .or_else(|| non_empty(result.compliance.as_deref()).map(clean_text));
            let test_type = non_empty(details.test_type.as_deref());
            let test = non_empty(details.test.as_deref());
            let solution = non_empty(details.solution.as_deref());
            let notes = non_empty(details.notes.as_deref());
            if compliant.is_some()
                || actual_value.is_some()
                || set_point.is_some()
                || test_type.is_some()
                || test.is_some()
                || solution.is_some()
                || notes.is_some()
            {
                self.write_compliance_detail_heading("Compliance Detection Result");
                if let Some(value) = compliant.as_deref() {
                    self.write_compliance_labeled_value("Compliant", value);
                }
                if let Some(value) = actual_value {
                    self.write_compliance_labeled_value("Actual Value", value);
                }
                if let Some(value) = set_point {
                    self.write_compliance_labeled_value("Set Point", value);
                }
            }

            if test_type.is_some() || test.is_some() || solution.is_some() || notes.is_some() {
                if let Some(value) = test_type {
                    self.write_compliance_labeled_value("Type of Test", value);
                }
                if let Some(value) = test {
                    self.write_compliance_labeled_value("Test", value);
                }
                if let Some(value) = solution {
                    self.write_compliance_labeled_value("Solution", value);
                }
                if let Some(value) = notes {
                    self.write_compliance_labeled_value("Notes", value);
                }
            }
        } else if let Some(description) = non_empty(result.description.as_deref()) {
            self.write_compliance_text_section("Result", description);
        }

        if let Some(method) = detection_method(result) {
            self.write_compliance_detail_heading("Compliance Detection Method");
            self.write_compliance_text(&method, true);
        }

        let references = result_references(result);
        if !references.is_empty() {
            self.write_compliance_detail_heading("References");
            self.write_compliance_text(&references.join("\n"), true);
        }
    }

    fn write_delta_compliance_result(&mut self, title: &str, result: &ReportResult) {
        let Some(delta) = result.delta.as_ref() else {
            self.write_compliance_result_card(title, result);
            return;
        };

        let Some(state) = delta.state() else {
            self.write_compliance_result_card(title, result);
            return;
        };

        self.write_delta_marker(state);

        match state {
            DeltaState::Same | DeltaState::New | DeltaState::Gone => {
                self.write_compliance_result_card(title, result);
            }
            DeltaState::Changed => {
                self.write_compliance_result_heading(title);
                self.write_compliance_detail_heading("Current Result");
                self.write_compliance_result_card_body(result);

                if let Some(previous) = delta.previous_result() {
                    self.write_compliance_detail_heading("Previous Result");
                    self.write_compliance_result_card_body(previous);
                }

                if let Some(diff) = delta.diff.as_deref().filter(|diff| !diff.trim().is_empty()) {
                    self.write_compliance_detail_heading("Different Lines");
                    self.write_diff_block(diff);
                }
            }
        }
    }

    fn write_compliance_status(&mut self, result: &ReportResult) {
        let text = compliance_display_upper(result);
        let (fill, text_color) = compliance_colors(result);

        self.ensure_space(7.0);
        self.pdf.set_font("Helvetica", "B", Unit::pt(8.0));
        self.pdf.set_fill_color(fill);
        self.pdf.set_text_color(text_color);
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(7.0),
            &format!("Compliance: {text}"),
            "1",
            1,
            "L",
            true,
            0,
            "",
        );
        self.pdf.set_fill_color(RGB::new(255, 255, 255));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf
            .set_font("Helvetica", "", Unit::pt(COMPLIANCE_BODY_FONT_PT));
    }

    fn write_compliance_nvt_header(&mut self, name: &str, result: &ReportResult) {
        let (fill, text_color) = compliance_colors(result);
        self.ensure_space(7.0);
        self.pdf.set_font("Helvetica", "B", Unit::pt(8.5));
        self.pdf.set_fill_color(fill);
        self.pdf.set_text_color(text_color);
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(7.0),
            &format!("NVT: {}", clean_text(name)),
            "1",
            1,
            "L",
            true,
            0,
            "",
        );
        self.pdf.set_fill_color(RGB::new(255, 255, 255));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
    }

    fn write_compliance_text_section(&mut self, heading: &str, value: &str) {
        self.write_compliance_detail_heading(heading);
        self.write_compliance_text(value, true);
    }

    fn write_compliance_labeled_value(&mut self, label: &str, value: &str) {
        self.ensure_space(5.0);
        let (x, y) = self.pdf.get_xy();
        let start_page = self.pdf.page_no();
        self.pdf
            .set_font("Helvetica", "B", Unit::pt(COMPLIANCE_BODY_FONT_PT));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.cell_format(
            Unit::mm(COMPLIANCE_LABEL_WIDTH_MM),
            Unit::mm(COMPLIANCE_LINE_HEIGHT_MM),
            &format!("{label}:"),
            "",
            0,
            "L",
            false,
            0,
            "",
        );
        self.pdf.set_xy(x + Unit::mm(COMPLIANCE_LABEL_WIDTH_MM), y);
        self.pdf
            .set_font("Helvetica", "", Unit::pt(COMPLIANCE_BODY_FONT_PT));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM - COMPLIANCE_LABEL_WIDTH_MM),
            Unit::mm(COMPLIANCE_LINE_HEIGHT_MM),
            &clean_text(value.trim()),
            "",
            "L",
            false,
        );
        if self.pdf.page_no() == start_page {
            let (_, end_y) = self.pdf.get_xy();
            self.pdf
                .rect(x, y, Unit::mm(CONTENT_WIDTH_MM), end_y - y, "D");
            self.pdf.set_xy(x, end_y);
        }
    }

    fn write_compliance_detail_heading(&mut self, heading: &str) {
        self.ensure_space(10.0);
        self.pdf.set_font("Helvetica", "B", Unit::pt(9.0));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.set_fill_color(RGB::new(248, 248, 248));
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(5.5),
            heading,
            "1",
            1,
            "L",
            true,
            0,
            "",
        );
        self.pdf.set_fill_color(RGB::new(255, 255, 255));
    }

    fn write_compliance_result_heading(&mut self, heading: &str) {
        self.ensure_space(24.0);
        self.pdf.set_font("Helvetica", "B", Unit::pt(10.0));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(6.5),
            heading,
            "",
            1,
            "L",
            false,
            0,
            "",
        );
    }

    fn write_compliance_text(&mut self, value: &str, framed: bool) {
        self.ensure_space(COMPLIANCE_LINE_HEIGHT_MM + 1.0);
        let (start_x, start_y) = self.pdf.get_xy();
        let start_page = self.pdf.page_no();
        self.pdf
            .set_font("Helvetica", "", Unit::pt(COMPLIANCE_BODY_FONT_PT));
        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(COMPLIANCE_LINE_HEIGHT_MM),
            &clean_text(value.trim()),
            "",
            "L",
            false,
        );
        if framed && self.pdf.page_no() == start_page {
            let (_, end_y) = self.pdf.get_xy();
            self.pdf.rect(
                start_x,
                start_y,
                Unit::mm(CONTENT_WIDTH_MM),
                end_y - start_y,
                "D",
            );
            self.pdf.set_xy(start_x, end_y);
        }
    }
}

fn filtered_or_full(value: &FullFiltered) -> Option<&str> {
    value.filtered.as_deref().or(value.full.as_deref())
}

fn parse_count(value: &str) -> Option<usize> {
    value.trim().parse().ok()
}

fn compliance_value(value: &crate::domain::report_model::ComplianceSummary) -> Option<String> {
    value
        .filtered
        .as_deref()
        .or(value.full.as_deref())
        .map(str::to_string)
}

fn compliance_percentage(yes: usize, total: usize) -> Option<f64> {
    (total > 0).then(|| yes as f64 / total as f64 * 100.0)
}

fn sum_host_values(rows: &[(String, [String; 5])], index: usize) -> String {
    let mut total = 0usize;
    let mut found = false;

    for (_, values) in rows {
        if let Ok(value) = values[index].parse::<usize>() {
            total += value;
            found = true;
        }
    }

    if found {
        total.to_string()
    } else {
        String::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DeltaStateCounts {
    changed: usize,
    new: usize,
    gone: usize,
    same: usize,
}

fn delta_state_counts(results: &[ReportResult]) -> DeltaStateCounts {
    let mut counts = DeltaStateCounts::default();

    for state in results
        .iter()
        .filter_map(|result| result.delta.as_ref())
        .filter_map(|delta| delta.state())
    {
        match state {
            DeltaState::Changed => counts.changed += 1,
            DeltaState::New => counts.new += 1,
            DeltaState::Gone => counts.gone += 1,
            DeltaState::Same => counts.same += 1,
        }
    }

    counts
}

fn compliance_display_status(result: &ReportResult) -> ComplianceDisplayStatus {
    match result.compliance_status() {
        Some(ComplianceStatus::Yes) => ComplianceDisplayStatus::Yes,
        Some(ComplianceStatus::No) => ComplianceDisplayStatus::No,
        Some(ComplianceStatus::Incomplete) => ComplianceDisplayStatus::Incomplete,
        Some(ComplianceStatus::Undefined) if result.compliance_details().is_some() => {
            ComplianceDisplayStatus::Undefined
        }
        Some(ComplianceStatus::Undefined) | None => ComplianceDisplayStatus::Log,
    }
}

fn compliance_display_label(result: &ReportResult) -> &'static str {
    match compliance_display_status(result) {
        ComplianceDisplayStatus::Yes => "yes",
        ComplianceDisplayStatus::No => "no",
        ComplianceDisplayStatus::Incomplete => "incomplete",
        ComplianceDisplayStatus::Log => "Log",
        ComplianceDisplayStatus::Undefined => "undefined",
    }
}

pub(crate) fn compliance_display_upper(result: &ReportResult) -> String {
    match compliance_display_status(result) {
        ComplianceDisplayStatus::Yes => "YES".to_string(),
        ComplianceDisplayStatus::No => "NO".to_string(),
        ComplianceDisplayStatus::Incomplete => "INCOMPLETE".to_string(),
        ComplianceDisplayStatus::Log => "Log".to_string(),
        ComplianceDisplayStatus::Undefined => "UNDEFINED".to_string(),
    }
}

fn compliance_display(result: &ReportResult) -> String {
    compliance_display_label(result).to_string()
}

fn compliance_colors(result: &ReportResult) -> (RGB, RGB) {
    match compliance_display_status(result) {
        ComplianceDisplayStatus::Yes => (RGB::new(70, 135, 75), RGB::new(255, 255, 255)),
        ComplianceDisplayStatus::No => (RGB::new(180, 65, 65), RGB::new(255, 255, 255)),
        ComplianceDisplayStatus::Incomplete => (RGB::new(210, 150, 45), RGB::new(0, 0, 0)),
        ComplianceDisplayStatus::Log | ComplianceDisplayStatus::Undefined => {
            (RGB::new(110, 110, 110), RGB::new(255, 255, 255))
        }
    }
}

fn compliance_status_text(status: ComplianceStatus) -> &'static str {
    match status {
        ComplianceStatus::Yes => "YES",
        ComplianceStatus::No => "NO",
        ComplianceStatus::Incomplete => "INCOMPLETE",
        ComplianceStatus::Undefined => "UNDEFINED",
    }
}

pub(crate) fn compliance_sort_rank(result: &ReportResult) -> u8 {
    match compliance_display_status(result) {
        ComplianceDisplayStatus::Yes => 0,
        ComplianceDisplayStatus::No => 1,
        ComplianceDisplayStatus::Incomplete => 2,
        ComplianceDisplayStatus::Log => 3,
        ComplianceDisplayStatus::Undefined => 4,
    }
}

pub(crate) fn sort_compliance_results(results: &[ReportResult]) -> Vec<ReportResult> {
    let mut sorted = results.to_vec();
    sorted.sort_by_key(compliance_sort_rank);
    sorted
}

pub(crate) fn compliance_result_heading(number: &str, result: &ReportResult) -> String {
    format!(
        "{number} {} {}",
        compliance_display_upper(result),
        result_port(result)
    )
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn non_empty_text(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn wrap_nvt_name(value: &str, max_chars: usize) -> String {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in value.split_whitespace() {
        if word.chars().count() > max_chars {
            if !current.is_empty() {
                lines.push(current);
                current = String::new();
            }

            let mut chunk = String::new();
            for character in word.chars() {
                if chunk.chars().count() == max_chars {
                    lines.push(chunk);
                    chunk = String::new();
                }
                chunk.push(character);
            }
            if !chunk.is_empty() {
                current = chunk;
            }
            continue;
        }

        let next_len = if current.is_empty() {
            word.chars().count()
        } else {
            current.chars().count() + 1 + word.chars().count()
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

    if lines.is_empty() {
        "-".to_string()
    } else {
        lines.join("\n")
    }
}

#[cfg(test)]
#[path = "compliance_tests.rs"]
mod compliance_tests;
