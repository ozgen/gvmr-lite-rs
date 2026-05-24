use std::collections::BTreeSet;

use crate::{
    domain::report_model::{ReportEnvelope, ReportResult},
    service::pdf_renderer_helper::{result_host, result_port, result_threat},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportTargetKind {
    Host,
    ContainerImage,
    Agent,
}

impl ReportTargetKind {
    pub(crate) fn from_report(report: &ReportEnvelope) -> Self {
        if report.report.is_container_image_report() {
            Self::ContainerImage
        } else if report.report.is_agent_report() {
            Self::Agent
        } else {
            Self::Host
        }
    }

    pub(crate) fn overview_column(self) -> &'static str {
        match self {
            Self::Host => "Host",
            Self::ContainerImage => "Image",
            Self::Agent => "Agent",
        }
    }

    pub(crate) fn results_section_title(self) -> &'static str {
        match self {
            Self::Host => "Results per Host",
            Self::ContainerImage => "Results per Image",
            Self::Agent => "Results per Agent",
        }
    }

    pub(crate) fn scan_start_label(self) -> &'static str {
        match self {
            Self::Host => "Host scan start",
            Self::ContainerImage => "Image scan start",
            Self::Agent => "Agent scan start",
        }
    }

    pub(crate) fn scan_end_label(self) -> &'static str {
        match self {
            Self::Host => "Host scan end",
            Self::ContainerImage => "Image scan end",
            Self::Agent => "Agent scan end",
        }
    }

    pub(crate) fn finding_title(self, result: &ReportResult) -> String {
        let threat = result_threat(result);

        match self {
            Self::Host => format!("{threat} {}", result_port(result)),
            Self::ContainerImage | Self::Agent => threat.to_string(),
        }
    }

    pub(crate) fn is_grouped_by_threat(self) -> bool {
        matches!(self, Self::ContainerImage | Self::Agent)
    }
}

pub(crate) fn image_display_name(result: &ReportResult) -> String {
    result
        .target_display_name()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| result_host(result).to_string())
}

pub(crate) fn grouped_threats(results: &[ReportResult]) -> Vec<String> {
    let mut seen = BTreeSet::new();

    for result in results {
        let threat = result_threat(result).trim();

        if !threat.is_empty() {
            seen.insert(threat.to_string());
        }
    }

    let order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Log",
        "False Positive",
        "False P.",
    ];

    let mut ordered = Vec::new();

    for threat in order {
        if seen.remove(threat) {
            ordered.push(threat.to_string());
        }
    }

    ordered.extend(seen);
    ordered
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod target_tests;
