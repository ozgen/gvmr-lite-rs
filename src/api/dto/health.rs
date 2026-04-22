use std::path::PathBuf;

use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct LiveResponse {
    pub status: &'static str,
}

impl LiveResponse {
    pub fn ok() -> Self {
        Self { status: "ok" }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadyResponse {
    pub status: String,
    pub feed_dir: String,
    pub work_dir: String,
    pub feed_exists: bool,
    pub work_exists: bool,
    pub formats_count: usize,
}

impl ReadyResponse {
    pub fn from_health_state(
        feed_dir: PathBuf,
        work_dir: PathBuf,
        feed_exists: bool,
        work_exists: bool,
        formats_count: usize,
    ) -> Self {
        let status = if feed_exists { "ok" } else { "not_ready" }.to_string();

        Self {
            status,
            feed_dir: feed_dir.display().to_string(),
            work_dir: work_dir.display().to_string(),
            feed_exists,
            work_exists,
            formats_count,
        }
    }
}