use super::*;

#[test]
fn new_typst_work_dir_path_contains_project_prefix() {
    let path = new_typst_work_dir_path();

    let path = path.to_string_lossy();

    assert!(path.contains("gvmr-lite-rs-typst-"));
}

#[test]
fn create_typst_work_dir_creates_directory() {
    let path = create_typst_work_dir().expect("work dir should be created");

    assert!(path.exists());
    assert!(path.is_dir());

    let _ = std::fs::remove_dir_all(path);
}
