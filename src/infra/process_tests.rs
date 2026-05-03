use std::{collections::HashMap, path::Path};

use super::run_cmd;

#[tokio::test]
async fn run_cmd_returns_stdout_on_success() {
    let args = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf hello".to_string(),
    ];

    let output = run_cmd(&args, Path::new("."), None, 5).await.unwrap();

    assert_eq!(output.returncode, 0);
    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn run_cmd_returns_stderr_and_non_zero_code() {
    let args = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf error >&2; exit 7".to_string(),
    ];

    let output = run_cmd(&args, Path::new("."), None, 5).await.unwrap();

    assert_eq!(output.returncode, 7);
    assert_eq!(output.stderr, b"error");
}

#[tokio::test]
async fn run_cmd_rejects_empty_args() {
    let result = run_cmd(&[], Path::new("."), None, 5).await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn run_cmd_passes_env_vars() {
    let args = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf \"$GVMR_TEST_VALUE\"".to_string(),
    ];

    let mut envs = HashMap::new();
    envs.insert("GVMR_TEST_VALUE".to_string(), "works".to_string());

    let output = run_cmd(&args, Path::new("."), Some(&envs), 5)
        .await
        .unwrap();

    assert_eq!(output.returncode, 0);
    assert_eq!(output.stdout, b"works");
}

#[tokio::test]
async fn run_cmd_times_out() {
    let args = vec!["sh".to_string(), "-c".to_string(), "sleep 2".to_string()];

    let result = run_cmd(&args, Path::new("."), None, 1).await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn run_cmd_runs_inside_given_cwd() {
    let temp_dir = tempfile::tempdir().unwrap();

    let args = vec!["sh".to_string(), "-c".to_string(), "pwd".to_string()];

    let output = run_cmd(&args, temp_dir.path(), None, 5).await.unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), temp_dir.path().to_string_lossy());
}
