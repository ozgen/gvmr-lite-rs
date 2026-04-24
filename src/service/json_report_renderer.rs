use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tracing::{info, warn};

use crate::{
    domain::report_format::ReportFormat,
    infra::process::run_cmd,
    service::{
        report_json_injector::inject_graph_gen_fields, report_xml_builder::build_report_xml,
    },
};

#[derive(Debug, Error)]
pub enum RenderError {
    #[error("generate script not found for format {format_id}")]
    GenerateScriptNotFound { format_id: String },

    #[error("generate script not present in temporary workdir for format {format_id}")]
    GenerateScriptMissingInTempDir { format_id: String },

    #[error("failed to create render temp directory: {0}")]
    TempDir(std::io::Error),

    #[error("failed to write report.xml: {0}")]
    WriteReport(std::io::Error),

    #[error("failed to copy report format assets: {0}")]
    CopyAssets(std::io::Error),

    #[error("failed to run render command: {0}")]
    RunCommand(std::io::Error),

    #[error("failed to read render output file: {0}")]
    ReadOutput(std::io::Error),

    #[error("failed to build report XML: {0}")]
    BuildXml(String),

    #[error(
        "render produced no output\nformat_id={format_id}\nreturncode={returncode}\nstderr={stderr}\ntmp_files={tmp_files:?}"
    )]
    NoOutput {
        format_id: String,
        returncode: i32,
        stderr: String,
        tmp_files: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct RenderResult {
    pub content: Vec<u8>,
    pub content_type: String,
    pub filename: String,
}

#[derive(Debug, Clone, Default)]
pub struct JsonReportRenderer;

impl JsonReportRenderer {
    pub async fn render(
        &self,
        fmt: &ReportFormat,
        report_json: &serde_json::Value,
        params: &serde_json::Map<String, serde_json::Value>,
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

        let injected = inject_graph_gen_fields(report_json).map_err(RenderError::BuildXml)?;

        let report_payload = injected.get("report").unwrap_or(&injected);
        let report_xml = build_report_xml(&serde_json::json!({ "report": report_payload }))
            .map_err(|err| RenderError::BuildXml(err.to_string()))?;

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

        let mut assets =
            copy_format_assets(&fmt.workdir, tmp_path).map_err(RenderError::CopyAssets)?;
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
            && let Some(out_file) =
                pick_output_file(tmp_path, &before, &assets, Some(&fmt.extension))
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
                tmp_files = ?list_files(tmp_path),
                "render produced no output"
            );
        
            return Err(RenderError::NoOutput {
                format_id: fmt.id.clone(),
                returncode: output.returncode,
                stderr,
                tmp_files: list_files(tmp_path),
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
}

fn build_env(
    fmt: &ReportFormat,
    tmpdir: &Path,
    report_path: &Path,
    params: &serde_json::Map<String, serde_json::Value>,
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

fn param_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(v) => v.to_string(),
        serde_json::Value::Null => String::new(),
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

fn walk_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if !root.exists() {
        return Ok(files);
    }

    for entry in fs::read_dir(root)? {
        let path = entry?.path();

        if path.is_dir() {
            files.extend(walk_files(&path)?);
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(files)
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
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);
        let size = metadata.map(|m| m.len()).unwrap_or(0);

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

fn list_files(tmpdir: &Path) -> Vec<String> {
    walk_files(tmpdir)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(tmpdir)
                .ok()
                .map(|rel| rel.display().to_string())
        })
        .collect()
}

fn fallback_extension(extension: &str) -> &str {
    let extension = extension.trim().trim_start_matches('.');

    if extension.is_empty() {
        "bin"
    } else {
        extension
    }
}

#[cfg(unix)]
fn make_executable_best_effort(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        let _ = fs::set_permissions(path, permissions);
    }
}

#[cfg(not(unix))]
fn make_executable_best_effort(_path: &Path) {}

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

    let debug_dir = debug_root.join(format!("{format_id}-{}", current_unix_timestamp()));

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

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if src_path.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
