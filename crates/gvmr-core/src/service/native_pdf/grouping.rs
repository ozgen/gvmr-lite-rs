use std::collections::BTreeMap;

use crate::{
    domain::report_model::{ReportHost, ReportResult},
    service::pdf_renderer_helper::{all_results, result_host},
};

use super::{
    document::NativePdfDocument,
    target::{ReportTargetKind, image_display_name},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingKey {
    pub(crate) host: String,
    pub(crate) index: usize,
}

impl<'a> NativePdfDocument<'a> {
    pub(crate) fn group_results_by_target(&self) -> BTreeMap<String, Vec<ReportResult>> {
        let mut grouped: BTreeMap<String, Vec<ReportResult>> = BTreeMap::new();

        for result in all_results(self.report) {
            grouped
                .entry(self.target_key_for_result(result))
                .or_default()
                .push(result.clone());
        }

        grouped
    }

    pub(crate) fn target_key_for_result(&self, result: &ReportResult) -> String {
        match self.target_kind {
            ReportTargetKind::Host => result_host(result).to_string(),

            ReportTargetKind::ContainerImage => image_display_name(result),

            ReportTargetKind::Agent => self
                .agent_id_for_result(result)
                .unwrap_or_else(|| result_host(result).to_string()),
        }
    }

    pub(crate) fn host_detail_for_result(&self, result: &ReportResult) -> Option<&ReportHost> {
        let host_key = result
            .target_address()
            .unwrap_or_else(|| result_host(result));

        self.report
            .report
            .hosts_detail
            .iter()
            .find(|host| host.address() == Some(host_key))
    }

    pub(crate) fn agent_id_for_result(&self, result: &ReportResult) -> Option<String> {
        self.host_detail_for_result(result)
            .and_then(ReportHost::agent_id)
            .map(ToOwned::to_owned)
    }
}

#[cfg(test)]
#[path = "grouping_tests.rs"]
mod grouping_tests;
