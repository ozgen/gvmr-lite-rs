use std::{collections::HashSet, fs};

use super::*;

fn names(values: &[&str]) -> HashSet<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn ensure_dir_creates_nested_directory() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("a/b/c");

    ensure_dir(&path).unwrap();

    assert!(path.is_dir());
}

#[test]
fn write_bytes_atomic_creates_parent_and_writes_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("nested/file.txt");

    write_bytes_atomic(&path, b"hello").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"hello");
    assert!(!temp_dir.path().join("nested/.file.txt.tmp").exists());
}

#[test]
fn write_bytes_atomic_rejects_path_without_parent() {
    let result = write_bytes_atomic("file.txt".as_ref(), b"hello");

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn delete_stale_dirs_removes_only_unwanted_dirs() {
    let temp_dir = tempfile::tempdir().unwrap();

    fs::create_dir(temp_dir.path().join("keep")).unwrap();
    fs::create_dir(temp_dir.path().join("remove")).unwrap();
    fs::write(temp_dir.path().join("file.txt"), b"not a dir").unwrap();

    delete_stale_dirs(temp_dir.path(), &names(&["keep"])).unwrap();

    assert!(temp_dir.path().join("keep").is_dir());
    assert!(!temp_dir.path().join("remove").exists());
    assert!(temp_dir.path().join("file.txt").is_file());
}

#[test]
fn delete_stale_dirs_ignores_missing_parent() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");

    delete_stale_dirs(&missing, &HashSet::new()).unwrap();
}

#[test]
fn delete_stale_files_removes_only_unwanted_files() {
    let temp_dir = tempfile::tempdir().unwrap();

    fs::write(temp_dir.path().join("keep.txt"), b"keep").unwrap();
    fs::write(temp_dir.path().join("remove.txt"), b"remove").unwrap();
    fs::create_dir(temp_dir.path().join("dir")).unwrap();

    delete_stale_files(temp_dir.path(), &names(&["keep.txt"])).unwrap();

    assert!(temp_dir.path().join("keep.txt").is_file());
    assert!(!temp_dir.path().join("remove.txt").exists());
    assert!(temp_dir.path().join("dir").is_dir());
}

#[test]
fn delete_stale_files_ignores_missing_parent() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");

    delete_stale_files(&missing, &HashSet::new()).unwrap();
}

#[test]
fn copy_dir_recursive_copies_nested_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src = temp_dir.path().join("src");
    let dst = temp_dir.path().join("dst");

    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("root.txt"), b"root").unwrap();
    fs::write(src.join("nested/child.txt"), b"child").unwrap();

    copy_dir_recursive(&src, &dst).unwrap();

    assert_eq!(fs::read(dst.join("root.txt")).unwrap(), b"root");
    assert_eq!(fs::read(dst.join("nested/child.txt")).unwrap(), b"child");
}

#[test]
fn walk_files_returns_all_files_recursively() {
    let temp_dir = tempfile::tempdir().unwrap();

    fs::create_dir_all(temp_dir.path().join("a/b")).unwrap();
    fs::write(temp_dir.path().join("one.txt"), b"1").unwrap();
    fs::write(temp_dir.path().join("a/two.txt"), b"2").unwrap();
    fs::write(temp_dir.path().join("a/b/three.txt"), b"3").unwrap();

    let mut files = walk_files(temp_dir.path())
        .unwrap()
        .into_iter()
        .map(|path| {
            path.strip_prefix(temp_dir.path())
                .unwrap()
                .display()
                .to_string()
        })
        .collect::<Vec<_>>();

    files.sort();

    assert_eq!(files, vec!["a/b/three.txt", "a/two.txt", "one.txt"]);
}

#[test]
fn walk_files_returns_empty_for_missing_root() {
    let temp_dir = tempfile::tempdir().unwrap();

    let files = walk_files(&temp_dir.path().join("missing")).unwrap();

    assert!(files.is_empty());
}

#[test]
fn list_relative_files_returns_relative_paths() {
    let temp_dir = tempfile::tempdir().unwrap();

    fs::create_dir_all(temp_dir.path().join("nested")).unwrap();
    fs::write(temp_dir.path().join("nested/file.txt"), b"hello").unwrap();

    let files = list_relative_files(temp_dir.path());

    assert_eq!(files, vec!["nested/file.txt"]);
}

#[test]
fn make_executable_best_effort_does_not_fail_for_missing_file() {
    let temp_dir = tempfile::tempdir().unwrap();

    make_executable_best_effort(&temp_dir.path().join("missing"));
}

#[cfg(unix)]
#[test]
fn maybe_make_executable_sets_executable_bit_for_shebang_file() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("script.sh");

    fs::write(&path, b"#!/bin/sh\necho hello\n").unwrap();

    maybe_make_executable(&path, b"#!/bin/sh\necho hello\n").unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_ne!(mode & 0o111, 0);
}

#[cfg(unix)]
#[test]
fn maybe_make_executable_leaves_regular_file_non_executable() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("file.txt");

    fs::write(&path, b"hello").unwrap();

    maybe_make_executable(&path, b"hello").unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o111, 0);
}
