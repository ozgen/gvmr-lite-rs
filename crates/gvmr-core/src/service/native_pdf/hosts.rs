use std::collections::BTreeMap;

use fpdf::{Pdf, RGB, Unit};

use crate::{
    domain::report_model::ReportResult,
    service::pdf_renderer_helper::clean_text,
    service::report_view::{ReportTargetKind, grouped_threats, result_port, result_threat},
};

use super::{
    constants::{A4_WIDTH_MM, CONTENT_WIDTH_MM},
    document::NativePdfDocument,
    grouping::FindingKey,
};

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn write_results_per_host(&mut self) {
        let grouped = self.group_results_by_target();

        if grouped.is_empty() {
            return;
        }

        self.pdf.add_page();

        let page = self.pdf.page_no();
        self.set_toc_page("2", page);
        self.set_link_here(self.toc_link("2"), page);

        self.write_heading(&format!("2 {}", self.target.results_section_title()), 1);

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
            self.write_service_table(target, results);

            if self.target.is_grouped_by_threat() {
                self.write_container_findings_by_threat(&target_number, target, results);
            } else {
                self.write_host_findings(&target_number, target, results);
            }
        }
    }

    pub(crate) fn write_target_scan_times(&mut self, _target: &str, results: &[ReportResult]) {
        let Some(host_key) = results.first().and_then(ReportResult::target_address) else {
            return;
        };

        let Some(detail) = self
            .report
            .report
            .hosts_detail
            .iter()
            .find(|detail| detail.address() == Some(host_key))
        else {
            return;
        };

        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));

        if let Some(start) = detail
            .start
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM),
                Unit::mm(5.0),
                &format!("{} {}", self.target.scan_start_label(), clean_text(start)),
                "",
                1,
                "L",
                false,
                0,
                "",
            );
        }

        if let Some(end) = detail
            .end
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM),
                Unit::mm(5.0),
                &format!("{} {}", self.target.scan_end_label(), clean_text(end)),
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

    pub(crate) fn write_target_metadata(&mut self, results: &[ReportResult]) {
        if self.target != ReportTargetKind::ContainerImage {
            return;
        }

        let Some(result) = results.first() else {
            return;
        };

        self.pdf.set_font("Helvetica", "", Unit::pt(8.0));

        if let Some(name) = result.image_full_name() {
            self.pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM),
                Unit::mm(5.0),
                &format!("Image name {}", clean_text(name)),
                "",
                1,
                "L",
                false,
                0,
                "",
            );
        }

        if let Some(digest) = result.image_digest() {
            self.pdf.cell_format(
                Unit::mm(CONTENT_WIDTH_MM),
                Unit::mm(5.0),
                &format!("Image digest {}", clean_text(digest)),
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

    pub(crate) fn write_service_table(&mut self, target: &str, results: &[ReportResult]) {
        if self.target.is_grouped_by_threat() {
            self.write_container_service_table(target, results);
        } else {
            self.write_host_service_table(target, results);
        }
    }

    fn write_container_service_table(&mut self, target: &str, results: &[ReportResult]) {
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
            "Service",
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

        for (threat_index, threat) in grouped_threats(results).iter().enumerate() {
            self.ensure_space(8.0);
            self.pdf.set_x(Unit::mm(x));

            let key = FindingKey {
                host: target.to_string(),
                index: threat_index,
            };

            let link = self.finding_links.get(&key).copied().unwrap_or(0);

            self.pdf.set_text_color(RGB::new(0, 90, 180));

            self.pdf.cell_format(
                Unit::mm(60.0),
                Unit::mm(6.0),
                "general",
                "1",
                0,
                "L",
                false,
                link,
                "",
            );

            self.pdf.cell_format(
                Unit::mm(40.0),
                Unit::mm(6.0),
                &clean_text(threat),
                "1",
                1,
                "L",
                false,
                link,
                "",
            );

            self.pdf.set_text_color(RGB::new(0, 0, 0));
        }

        self.pdf.ln(Unit::mm(5.0));
    }

    fn write_host_service_table(&mut self, target: &str, results: &[ReportResult]) {
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
                host: target.to_string(),
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

    fn write_container_findings_by_threat(
        &mut self,
        target_number: &str,
        target: &str,
        results: &[ReportResult],
    ) {
        let grouped = group_results_by_threat(results);

        for (group_index, (threat, group_results)) in grouped.iter().enumerate() {
            let section_number = format!("{target_number}.{}", group_index + 1);
            let page = self.pdf.page_no();

            self.set_toc_page(&section_number, page);

            let key = FindingKey {
                host: target.to_string(),
                index: group_index,
            };

            if let Some(link) = self.finding_links.get(&key).copied() {
                self.set_link_here(link, page);
            }

            self.write_heading(&format!("{section_number} {threat}"), 3);

            for result in group_results {
                let title = if let Some(severity) = result
                    .severity
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    format!("{threat} (CVSS: {severity})")
                } else {
                    threat.clone()
                };

                self.write_finding_card(&title, result);
            }
        }
    }

    fn write_host_findings(&mut self, target_number: &str, target: &str, results: &[ReportResult]) {
        for (result_index, result) in results.iter().enumerate() {
            let finding_number = format!("{target_number}.{}", result_index + 1);
            let title = format!("{finding_number} {}", self.target.finding_title(result));

            let page = self.pdf.page_no();
            self.set_toc_page(&finding_number, page);

            let key = FindingKey {
                host: target.to_string(),
                index: result_index,
            };

            if let Some(link) = self.finding_links.get(&key).copied() {
                self.set_link_here(link, page);
            }

            self.write_finding_card(&title, result);
        }
    }

    pub(crate) fn target_display_name(&self, target: &str, results: &[ReportResult]) -> String {
        match self.target {
            ReportTargetKind::Host => target.to_string(),

            ReportTargetKind::Agent => target.to_string(),

            ReportTargetKind::ContainerImage => {
                let arch_suffix = results
                    .first()
                    .and_then(|result| self.image_architecture_for_result(result))
                    .map(|arch| format!("({arch})"));

                shorten_image_display_name(target, arch_suffix.as_deref(), 34)
            }
        }
    }

    fn image_architecture_for_result(&self, result: &ReportResult) -> Option<&str> {
        self.host_detail_for_result(result)
            .and_then(|host| host.architecture())
    }
}

fn group_results_by_threat(results: &[ReportResult]) -> Vec<(String, Vec<ReportResult>)> {
    let mut grouped: BTreeMap<String, Vec<ReportResult>> = BTreeMap::new();

    for result in results {
        let threat = result_threat(result).trim();

        if threat.is_empty() {
            continue;
        }

        grouped
            .entry(threat.to_string())
            .or_default()
            .push(result.clone());
    }

    let order = ["Critical", "High", "Medium", "Low", "Log"];
    let mut ordered = Vec::new();

    for threat in order {
        if let Some(results) = grouped.remove(threat) {
            ordered.push((threat.to_string(), results));
        }
    }

    ordered.extend(grouped);

    ordered
}

fn shorten_image_display_name(name: &str, arch_suffix: Option<&str>, max_chars: usize) -> String {
    let name = name.trim();
    let suffix = arch_suffix.unwrap_or("");

    let suffix_len = suffix.chars().count();

    if suffix_len >= max_chars {
        return suffix.to_string();
    }

    let available_for_name = max_chars - suffix_len;

    if name.chars().count() <= available_for_name {
        return format!("{name}{suffix}");
    }

    if available_for_name <= 3 {
        return format!("...{suffix}");
    }

    let prefix_len = available_for_name - 3;
    let prefix: String = name.chars().take(prefix_len).collect();

    format!("{prefix}...{suffix}")
}

#[cfg(test)]
#[path = "hosts_test.rs"]
mod hosts_test;
