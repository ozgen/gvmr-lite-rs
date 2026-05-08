use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::{
    domain::report_format::ReportFormat,
    infra::{
        fs::{copy_dir_recursive, list_relative_files, make_executable_best_effort, walk_files},
        process::run_cmd,
    },
    service::report_renderer::{RenderError, RenderResult},
};

pub async fn render_report_xml_with_generate(
    fmt: &ReportFormat,
    report_xml: &str,
    params: &Map<String, Value>,
    timeout_seconds: u64,
    output_name: Option<&str>,
) -> Result<RenderResult, RenderError> {
    info!(
        format_id = %fmt.id,
        format_name = %fmt.name,
        timeout_seconds,
        output_name = ?output_name,
        "starting report render"
    );

    let generate_in_format = fmt.workdir.join("generate");

    if !generate_in_format.exists() {
        warn!(
            format_id = %fmt.id,
            generate_path = %generate_in_format.display(),
            "generate script not found"
        );

        return Err(RenderError::GenerateScriptNotFound {
            format_id: fmt.id.clone(),
        });
    }

    let tmpdir = tempfile::Builder::new()
        .prefix("gvmr-render-")
        .tempdir()
        .map_err(RenderError::TempDir)?;

    let tmp_path = tmpdir.path();

    let report_path = tmp_path.join("report.xml");
    fs::write(&report_path, report_xml.as_bytes()).map_err(RenderError::WriteReport)?;

    info!(
        format_id = %fmt.id,
        report_path = %report_path.display(),
        "report XML written"
    );

    let mut assets = copy_format_assets(&fmt.workdir, tmp_path).map_err(RenderError::CopyAssets)?;
    assets.insert(report_path.clone());

    let generate_path = tmp_path.join("generate");

    if !generate_path.exists() {
        maybe_copy_debug_tmpdir(&fmt.id, tmp_path);

        warn!(
            format_id = %fmt.id,
            generate_path = %generate_path.display(),
            "generate script missing in temporary workdir"
        );

        return Err(RenderError::GenerateScriptMissingInTempDir {
            format_id: fmt.id.clone(),
        });
    }

    make_executable_best_effort(&generate_path);
    assets.insert(generate_path);

    let before = snapshot_meta(tmp_path);
    let envs = build_env(fmt, tmp_path, &report_path, params);

    let args = vec![
        "/bin/sh".to_string(),
        "./generate".to_string(),
        "report.xml".to_string(),
    ];

    maybe_copy_debug_tmpdir(&fmt.id, tmp_path);

    let output = match run_cmd(&args, tmp_path, Some(&envs), timeout_seconds).await {
        Ok(output) => output,
        Err(err) => {
            maybe_copy_debug_tmpdir(&fmt.id, tmp_path);
            return Err(RenderError::RunCommand(err));
        }
    };

    info!(
        format_id = %fmt.id,
        returncode = output.returncode,
        stdout_len = output.stdout.len(),
        stderr_len = output.stderr.len(),
        "render command finished"
    );

    maybe_copy_debug_tmpdir(&fmt.id, tmp_path);

    let mut content = output.stdout;

    if content.is_empty()
        && let Some(out_file) = pick_output_file(tmp_path, &before, &assets, Some(&fmt.extension))
    {
        content = fs::read(out_file).map_err(RenderError::ReadOutput)?;
    }

    if content.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(4000)
            .collect::<String>();

        warn!(
            format_id = %fmt.id,
            returncode = output.returncode,
            stderr = %stderr,
            tmp_files = ?list_relative_files(tmp_path),
            "render produced no output"
        );

        return Err(RenderError::NoOutput {
            format_id: fmt.id.clone(),
            returncode: output.returncode,
            stderr,
            tmp_files: list_relative_files(tmp_path),
        });
    }

    let filename = output_name
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("report.{}", fallback_extension(&fmt.extension)));

    let content_type = if fmt.content_type.trim().is_empty() {
        "application/octet-stream".to_string()
    } else {
        fmt.content_type.clone()
    };

    info!(
        format_id = %fmt.id,
        filename = %filename,
        content_type = %content_type,
        content_len = content.len(),
        "report render completed"
    );

    Ok(RenderResult {
        content,
        content_type,
        filename,
    })
}

fn build_env(
    fmt: &ReportFormat,
    tmpdir: &Path,
    report_path: &Path,
    params: &Map<String, Value>,
) -> HashMap<String, String> {
    let mut envs: HashMap<String, String> = std::env::vars().collect();

    for (key, value) in params {
        envs.insert(
            format!("GVMR_PARAM_{}", key.to_uppercase()),
            param_value_to_string(value),
        );
    }

    envs.insert("GVMR_FORMAT_ID".to_string(), fmt.id.clone());
    envs.insert(
        "GVMR_FORMAT_DIR".to_string(),
        fmt.workdir.display().to_string(),
    );
    envs.insert("GVMR_WORK_DIR".to_string(), tmpdir.display().to_string());
    envs.insert(
        "GVMR_REPORT_PATH".to_string(),
        report_path.display().to_string(),
    );

    envs
}

fn param_value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn copy_format_assets(src_dir: &Path, dst_dir: &Path) -> std::io::Result<HashSet<PathBuf>> {
    let mut assets = HashSet::new();

    for src in walk_files(src_dir)? {
        let rel = src.strip_prefix(src_dir).unwrap_or(&src);
        let dst = dst_dir.join(rel);

        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::copy(&src, &dst)?;
        assets.insert(dst);
    }

    Ok(assets)
}

fn snapshot_meta(root: &Path) -> HashMap<PathBuf, (std::time::SystemTime, u64)> {
    let mut snapshot = HashMap::new();

    for path in walk_files(root).unwrap_or_default() {
        if let Ok(metadata) = fs::metadata(&path) {
            let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
            snapshot.insert(path, (modified, metadata.len()));
        }
    }

    snapshot
}

fn pick_output_file(
    tmpdir: &Path,
    before: &HashMap<PathBuf, (std::time::SystemTime, u64)>,
    assets: &HashSet<PathBuf>,
    preferred_ext: Option<&str>,
) -> Option<PathBuf> {
    let preferred_ext = preferred_ext
        .unwrap_or("")
        .trim_start_matches('.')
        .to_ascii_lowercase();

    let mut candidates = Vec::new();

    for path in walk_files(tmpdir).ok()? {
        if assets.contains(&path) {
            continue;
        }

        let changed = is_changed(&path, before);

        let ext_match = !preferred_ext.is_empty()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.eq_ignore_ascii_case(&preferred_ext))
                .unwrap_or(false);

        let score = match (changed, ext_match) {
            (true, true) => 3,
            (true, false) => 2,
            (false, true) => 1,
            (false, false) => 0,
        };

        let metadata = fs::metadata(&path).ok();

        let modified = metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);

        let size = metadata.map(|metadata| metadata.len()).unwrap_or(0);

        candidates.push((score, modified, size, path));
    }

    candidates.sort_by_key(|(score, modified, size, _)| (*score, *modified, *size));
    candidates.pop().map(|(_, _, _, path)| path)
}

fn is_changed(path: &Path, before: &HashMap<PathBuf, (std::time::SystemTime, u64)>) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
    let size = metadata.len();

    match before.get(path) {
        None => true,
        Some((old_modified, old_size)) => modified > *old_modified || size != *old_size,
    }
}

fn fallback_extension(extension: &str) -> &str {
    let extension = extension.trim().trim_start_matches('.');

    if extension.is_empty() {
        "bin"
    } else {
        extension
    }
}

fn maybe_copy_debug_tmpdir(format_id: &str, tmpdir: &Path) {
    let Ok(debug_root) = std::env::var("GVMR_RENDER_DEBUG_DIR") else {
        return;
    };

    let debug_root = PathBuf::from(debug_root);

    if let Err(err) = fs::create_dir_all(&debug_root) {
        tracing::warn!(
            debug_root = %debug_root.display(),
            error = %err,
            "failed to create render debug root"
        );
        return;
    }

    let debug_dir = debug_root.join(format!("{format_id}-{}", current_unix_timestamp_nanos()));

    if let Err(err) = copy_dir_recursive(tmpdir, &debug_dir) {
        tracing::warn!(
            tmpdir = %tmpdir.display(),
            debug_dir = %debug_dir.display(),
            error = %err,
            "failed to copy render debug temp directory"
        );
        return;
    }

    tracing::info!(
        debug_dir = %debug_dir.display(),
        "copied render temp directory for debugging"
    );
}

fn current_unix_timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
#[path = "script_render_runner_tests.rs"]
mod script_render_runner_tests;
