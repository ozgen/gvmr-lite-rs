use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use fpdf::{Fpdf, Orientation, PageSize, Pdf, RGB, Unit, UnitVec2};
use thiserror::Error;

use crate::{
    domain::report_model::{ReportEnvelope, ReportResult},
    service::pdf_renderer_helper::{
        all_results, clean_text, count_threat, detection_method, nvt_tag, report_date, result_host,
        result_name, result_port, result_qod, result_references, result_severity, result_solution,
        result_threat, severity_color, summary_text, truncate_text,
    },
};

const A4_WIDTH_MM: f64 = 210.0;
const A4_HEIGHT_MM: f64 = 297.0;
const LEFT_MARGIN_MM: f64 = 15.0;
const TOP_MARGIN_MM: f64 = 18.0;
const RIGHT_MARGIN_MM: f64 = 15.0;
const BOTTOM_MARGIN_MM: f64 = 18.0;
const CONTENT_WIDTH_MM: f64 = A4_WIDTH_MM - LEFT_MARGIN_MM - RIGHT_MARGIN_MM;

const MAX_FINDINGS: usize = 1_000;
const MAX_FIELD_CHARS: usize = 6_000;

#[derive(Debug, Error)]
pub enum NativePdfRenderError {
    #[error("failed to write native PDF to '{path}': {source}")]
    WritePdf {
        path: PathBuf,
        source: fpdf::FpdfError,
    },

    #[error("failed to read generated native PDF '{path}': {source}")]
    ReadPdf {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to remove native PDF temporary file '{path}': {source}")]
    Cleanup {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Default)]
pub struct NativePdfRenderer;

impl NativePdfRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, report: &ReportEnvelope) -> Result<Vec<u8>, NativePdfRenderError> {
        let mut pass1 = NativeTechnicalPdfRenderer::new(report);
        pass1.prepare_toc(None);
        pass1.write_cover();
        pass1.write_result_overview();
        pass1.write_results_per_host();

        let toc_pages = pass1.toc_pages();

        let mut pass2 = NativeTechnicalPdfRenderer::new(report);
        pass2.prepare_toc(Some(&toc_pages));
        pass2.render()
    }
}

#[derive(Debug, Clone)]
struct TocEntry {
    number: String,
    title: String,
    level: usize,
    page: usize,
    link: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingKey {
    host: String,
    index: usize,
}

struct NativeTechnicalPdfRenderer<'a> {
    pdf: Fpdf<'a>,
    report: &'a ReportEnvelope,
    host_links: BTreeMap<String, usize>,
    finding_links: BTreeMap<FindingKey, usize>,
    toc: Vec<TocEntry>,
}

impl<'a> NativeTechnicalPdfRenderer<'a> {
    fn new(report: &'a ReportEnvelope) -> Self {
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

        Self {
            pdf,
            report,
            host_links: BTreeMap::new(),
            finding_links: BTreeMap::new(),
            toc: Vec::new(),
        }
    }

    fn render(&mut self) -> Result<Vec<u8>, NativePdfRenderError> {
        self.write_cover();
        self.write_result_overview();
        self.write_results_per_host();

        self.output()
    }

    fn output(&mut self) -> Result<Vec<u8>, NativePdfRenderError> {
        let path = native_pdf_temp_path();

        self.pdf
            .output_file_and_close(path.to_string_lossy().as_ref())
            .map_err(|source| NativePdfRenderError::WritePdf {
                path: path.clone(),
                source,
            })?;

        let bytes = fs::read(&path).map_err(|source| NativePdfRenderError::ReadPdf {
            path: path.clone(),
            source,
        })?;

        if let Err(source) = fs::remove_file(&path) {
            return Err(NativePdfRenderError::Cleanup { path, source });
        }

        Ok(bytes)
    }

    fn prepare_toc(&mut self, known_pages: Option<&BTreeMap<String, usize>>) {
        self.toc.clear();
        self.host_links.clear();
        self.finding_links.clear();

        let overview_link = self.pdf.add_link();
        self.add_toc_entry("1", "Result Overview", 1, overview_link, known_pages);

        let results_link = self.pdf.add_link();
        self.add_toc_entry("2", "Results per Host", 1, results_link, known_pages);

        let grouped = self.group_results_by_host();

        for (host_index, (host, results)) in grouped.iter().enumerate() {
            let host_number = format!("2.{}", host_index + 1);
            let host_link = self.pdf.add_link();

            self.host_links.insert(host.clone(), host_link);
            self.add_toc_entry(&host_number, host, 2, host_link, known_pages);

            for (result_index, result) in results.iter().enumerate() {
                let finding_number = format!("{host_number}.{}", result_index + 1);
                let finding_link = self.pdf.add_link();

                let key = FindingKey {
                    host: host.clone(),
                    index: result_index,
                };

                self.finding_links.insert(key, finding_link);

                let title = format!("{} {}", result_threat(result), result_port(result),);

                self.add_toc_entry(&finding_number, &title, 3, finding_link, known_pages);
            }
        }
    }

    fn add_toc_entry(
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

    fn toc_pages(&self) -> BTreeMap<String, usize> {
        self.toc
            .iter()
            .map(|entry| (entry.number.clone(), entry.page))
            .collect()
    }

    fn set_toc_page(&mut self, number: &str, page: usize) {
        if let Some(entry) = self.toc.iter_mut().find(|entry| entry.number == number) {
            entry.page = page;
        }
    }

    fn toc_link(&self, number: &str) -> usize {
        self.toc
            .iter()
            .find(|entry| entry.number == number)
            .map(|entry| entry.link)
            .unwrap_or(0)
    }

    fn write_cover(&mut self) {
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
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(8.0),
            &clean_text(&report_date(self.report)),
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

    fn write_toc_entry(&mut self, entry: &TocEntry) {
        let row_h = 5.3;

        self.ensure_space(row_h + 1.0);

        let number_x = 25.0;
        let title_x = 45.0;
        let dots_x = 135.0;
        let page_x = 184.0;

        let number_w = title_x - number_x - 2.0;
        let title_w = dots_x - title_x - 2.0;
        let dots_w = page_x - dots_x - 2.0;
        let page_w = 9.0;

        let font_size = if entry.level >= 3 { 8.0 } else { 8.5 };
        let y = self.pdf.get_y();

        self.pdf.set_font("Helvetica", "", Unit::pt(font_size));

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

        self.pdf.set_xy(Unit::mm(title_x), y);
        self.pdf.cell_format(
            Unit::mm(title_w),
            Unit::mm(row_h),
            &clean_text(&entry.title),
            "",
            0,
            "L",
            false,
            entry.link,
            "",
        );

        self.pdf.set_text_color(RGB::new(0, 0, 0));
        self.pdf.set_xy(Unit::mm(dots_x), y);
        self.pdf.cell_format(
            Unit::mm(dots_w),
            Unit::mm(row_h),
            "................................................",
            "",
            0,
            "R",
            false,
            0,
            "",
        );

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

    fn write_result_overview(&mut self) {
        self.pdf.add_page();

        let page = self.pdf.page_no();
        self.set_toc_page("1", page);
        self.set_link_here(self.toc_link("1"), page);
        self.write_heading("1 Result Overview", 1);

        let headers = ["Host", "Critical", "High", "Medium", "Low", "Log"];
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
            let host = row.first().map(String::as_str).unwrap_or("");
            let host_link = self.host_links.get(host).copied().unwrap_or(0);

            for (index, cell) in row.iter().enumerate() {
                let is_host_cell = index == 0 && host != "Total" && host_link != 0;

                if is_host_cell {
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
                    if is_host_cell { host_link } else { 0 },
                    "",
                );
            }

            self.pdf.set_text_color(RGB::new(0, 0, 0));
            self.pdf.ln(Unit::negative());
        }

        self.pdf.ln(Unit::mm(8.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(9.0));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM),
            Unit::mm(5.0),
            "Only results matching the selected report filters are shown.",
            "",
            "L",
            false,
        );
    }

    fn write_results_per_host(&mut self) {
        let grouped = self.group_results_by_host();

        if grouped.is_empty() {
            return;
        }

        self.pdf.add_page();

        let page = self.pdf.page_no();
        self.set_toc_page("2", page);
        self.set_link_here(self.toc_link("2"), page);

        self.write_heading("2 Results per Host", 1);

        for (host_index, (host, results)) in grouped.iter().enumerate() {
            let host_number = format!("2.{}", host_index + 1);

            let page = self.pdf.page_no();
            self.set_toc_page(&host_number, page);

            if let Some(link) = self.host_links.get(host).copied() {
                self.set_link_here(link, page);
            }

            self.write_heading(&format!("{host_number} {host}"), 2);
            self.write_host_scan_times(host);
            self.write_service_table(host, results);

            for (result_index, result) in results.iter().enumerate() {
                let finding_number = format!("{host_number}.{}", result_index + 1);

                let title = format!(
                    "{} {} {}",
                    finding_number,
                    result_threat(result),
                    result_port(result)
                );

                let page = self.pdf.page_no();
                self.set_toc_page(&finding_number, page);

                let key = FindingKey {
                    host: host.clone(),
                    index: result_index,
                };

                if let Some(link) = self.finding_links.get(&key).copied() {
                    self.set_link_here(link, page);
                }

                self.write_finding_card(&title, result);
            }
        }
    }

    fn write_host_scan_times(&mut self, host: &str) {
        if let Some(detail) = self
            .report
            .report
            .hosts_detail
            .iter()
            .find(|detail| detail.ip.as_deref() == Some(host))
        {
            self.pdf.set_font("Helvetica", "", Unit::pt(8.0));

            if let Some(start) = detail.start.as_deref() {
                self.pdf.cell_format(
                    Unit::mm(CONTENT_WIDTH_MM),
                    Unit::mm(5.0),
                    &format!("Host scan start {}", clean_text(start)),
                    "",
                    1,
                    "L",
                    false,
                    0,
                    "",
                );
            }

            if let Some(end) = detail.end.as_deref() {
                self.pdf.cell_format(
                    Unit::mm(CONTENT_WIDTH_MM),
                    Unit::mm(5.0),
                    &format!("Host scan end {}", clean_text(end)),
                    "",
                    1,
                    "L",
                    false,
                    0,
                    "",
                );
            }

            self.pdf.ln(Unit::mm(2.0));
        }
    }

    fn write_service_table(&mut self, host: &str, results: &[ReportResult]) {
        self.ensure_space(25.0);

        let table_w = 100.0;
        let x = (A4_WIDTH_MM - table_w) / 2.0;
        self.pdf.set_x(Unit::mm(x));

        self.pdf.set_font("Helvetica", "B", Unit::pt(8.0));
        self.pdf.set_fill_color(RGB::new(220, 230, 240));
        self.pdf.set_text_color(RGB::new(0, 0, 0));

        self.pdf.cell_format(
            Unit::mm(60.0),
            Unit::mm(7.0),
            "Service (Port)",
            "1",
            0,
            "L",
            true,
            0,
            "",
        );

        self.pdf.cell_format(
            Unit::mm(40.0),
            Unit::mm(7.0),
            "Threat Level",
            "1",
            1,
            "L",
            true,
            0,
            "",
        );

        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));

        for (index, result) in results.iter().enumerate() {
            self.ensure_space(8.0);
            self.pdf.set_x(Unit::mm(x));

            let key = FindingKey {
                host: host.to_string(),
                index,
            };

            let link = self.finding_links.get(&key).copied().unwrap_or(0);

            self.pdf.set_text_color(RGB::new(0, 90, 180));

            self.pdf.cell_format(
                Unit::mm(60.0),
                Unit::mm(6.0),
                &clean_text(result_port(result)),
                "1",
                0,
                "L",
                false,
                link,
                "",
            );

            self.pdf.set_text_color(RGB::new(0, 0, 0));

            self.pdf.cell_format(
                Unit::mm(40.0),
                Unit::mm(6.0),
                &clean_text(result_threat(result)),
                "1",
                1,
                "L",
                false,
                link,
                "",
            );
        }

        self.pdf.ln(Unit::mm(5.0));
    }

    fn write_finding_card(&mut self, title: &str, result: &ReportResult) {
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

        self.write_box_field("Summary", nvt_tag(result, "summary"));

        if !result_qod(result).is_empty() {
            self.write_box_field(
                "Quality of Detection (QoD)",
                Some(format!("{}%", result_qod(result))),
            );
        }

        self.write_box_field("Vulnerability Detection Result", result.description.clone());

        self.write_box_field("Impact", nvt_tag(result, "impact"));
        self.write_box_field("Solution", result_solution(result));
        self.write_box_field("Affected Software/OS", nvt_tag(result, "affected"));
        self.write_box_field("Vulnerability Insight", nvt_tag(result, "insight"));
        self.write_box_field("Vulnerability Detection Method", detection_method(result));

        let refs = result_references(result);
        if !refs.is_empty() {
            self.write_box_field("References", Some(refs.join("\n")));
        }

        self.pdf.ln(Unit::mm(6.0));
    }

    fn write_box_field(&mut self, title: &str, value: Option<String>) {
        let Some(value) = value else {
            return;
        };

        let value = truncate_text(&clean_text(value.trim()), MAX_FIELD_CHARS);

        if value.trim().is_empty() {
            return;
        }

        let title_h = 5.0;
        let line_h = 4.5;
        let line_count = estimate_line_count(&value, 95).max(1);
        let body_h = title_h + (line_count as f64 * line_h) + 4.0;

        self.ensure_space(body_h);

        let (x, y) = self.pdf.get_xy();

        self.pdf
            .rect(x, y, Unit::mm(CONTENT_WIDTH_MM), Unit::mm(body_h), "D");

        self.pdf.set_xy(x + Unit::mm(2.0), y + Unit::mm(1.5));
        self.pdf.set_font("Helvetica", "B", Unit::pt(8.5));
        self.pdf.cell_format(
            Unit::mm(CONTENT_WIDTH_MM - 4.0),
            Unit::mm(title_h),
            title,
            "",
            1,
            "L",
            false,
            0,
            "",
        );

        self.pdf
            .set_xy(x + Unit::mm(2.0), y + Unit::mm(title_h + 1.0));
        self.pdf.set_font("Helvetica", "", Unit::pt(8.5));
        self.pdf.multi_cell(
            Unit::mm(CONTENT_WIDTH_MM - 4.0),
            Unit::mm(line_h),
            &value,
            "",
            "L",
            false,
        );

        self.pdf.set_xy(x, y + Unit::mm(body_h));
    }

    fn write_heading(&mut self, title: &str, level: usize) {
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

    fn ensure_space(&mut self, height_mm: f64) {
        let y = self.pdf.get_y().to_mm();

        if y + height_mm > A4_HEIGHT_MM - BOTTOM_MARGIN_MM {
            self.pdf.add_page();
        }
    }

    fn group_results_by_host(&self) -> BTreeMap<String, Vec<ReportResult>> {
        let mut grouped: BTreeMap<String, Vec<ReportResult>> = BTreeMap::new();

        for result in all_results(self.report).into_iter().take(MAX_FINDINGS) {
            grouped
                .entry(result_host(result).to_string())
                .or_default()
                .push(result.clone());
        }

        grouped
    }

    fn build_overview_rows(&self) -> Vec<Vec<String>> {
        let grouped = self.group_results_by_host();

        let mut rows = Vec::new();

        let mut total_critical = 0usize;
        let mut total_high = 0usize;
        let mut total_medium = 0usize;
        let mut total_low = 0usize;
        let mut total_log = 0usize;

        for (host, results) in grouped {
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

            rows.push(vec![
                host,
                critical.to_string(),
                high.to_string(),
                medium.to_string(),
                low.to_string(),
                log.to_string(),
            ]);
        }

        rows.push(vec![
            "Total".to_string(),
            total_critical.to_string(),
            total_high.to_string(),
            total_medium.to_string(),
            total_low.to_string(),
            total_log.to_string(),
        ]);

        rows
    }

    fn set_link_here(&mut self, link: usize, page: usize) {
        let y = self.pdf.get_y();

        let safe_y = if y.to_mm() < 0.0 { Unit::mm(0.0) } else { y };

        self.pdf.set_link(Some(safe_y), link, Some(page));
    }
}

fn estimate_line_count(text: &str, chars_per_line: usize) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    text.lines()
        .map(|line| {
            let len = line.chars().count();
            if len == 0 {
                1
            } else {
                (len / chars_per_line) + 1
            }
        })
        .sum()
}

fn native_pdf_temp_path() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    let pid = std::process::id();

    std::env::temp_dir().join(format!("gvmr-lite-rs-native-pdf-{pid}-{millis}.pdf"))
}

#[cfg(test)]
#[path = "native_pdf_renderer_tests.rs"]
mod native_pdf_renderer_tests;
