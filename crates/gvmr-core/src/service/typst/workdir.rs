use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::infra::fs::ensure_dir;

use super::error::TypstRenderError;

pub fn create_typst_work_dir() -> Result<PathBuf, TypstRenderError> {
    let work_dir = new_typst_work_dir_path();

    ensure_dir(&work_dir).map_err(|source| TypstRenderError::CreateWorkDir {
        path: work_dir.clone(),
        source,
    })?;

    Ok(work_dir)
}

fn new_typst_work_dir_path() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    let pid = std::process::id();

    std::env::temp_dir().join(format!("gvmr-lite-rs-typst-{pid}-{millis}"))
}

#[cfg(test)]
#[path = "workdir_tests.rs"]
mod workdir_tests;
