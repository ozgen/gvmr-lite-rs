use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};

pub fn ensure_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

pub fn write_bytes_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;

    fs::create_dir_all(parent)?;

    let tmp_path = temp_path(path);
    fs::write(&tmp_path, data)?;
    fs::rename(&tmp_path, path)?;

    Ok(())
}

pub fn delete_stale_dirs(parent: &Path, wanted_names: &HashSet<String>) -> io::Result<()> {
    if !parent.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if !wanted_names.contains(name) {
            fs::remove_dir_all(path)?;
        }
    }

    Ok(())
}

pub fn delete_stale_files(parent: &Path, wanted_names: &HashSet<String>) -> io::Result<()> {
    if !parent.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if !wanted_names.contains(name) {
            fs::remove_file(path)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
pub fn maybe_make_executable(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if looks_executable(data) {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn maybe_make_executable(_path: &Path, _data: &[u8]) -> io::Result<()> {
    Ok(())
}

pub fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
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

pub fn walk_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
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

pub fn list_relative_files(tmpdir: &Path) -> Vec<String> {
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

#[cfg(unix)]
pub fn make_executable_best_effort(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        let _ = fs::set_permissions(path, permissions);
    }
}

#[cfg(not(unix))]
pub fn make_executable_best_effort(_path: &Path) {}

fn looks_executable(data: &[u8]) -> bool {
    data.starts_with(b"#!")
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");

    path.with_file_name(format!(".{file_name}.tmp"))
}

#[cfg(test)]
#[path = "fs_tests.rs"]
mod fs_tests;
