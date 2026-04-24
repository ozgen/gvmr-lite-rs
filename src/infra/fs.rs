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
