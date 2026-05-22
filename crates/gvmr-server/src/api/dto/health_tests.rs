use std::path::PathBuf;

use super::{LiveResponse, ReadyResponse};

#[test]
fn live_response_ok_returns_ok_status() {
    let response = LiveResponse::ok();

    assert_eq!(response.status, "ok");
}

#[test]
fn ready_response_from_health_state_returns_ok_when_feed_exists() {
    let feed_dir = PathBuf::from("/tmp/feed");
    let work_dir = PathBuf::from("/tmp/work");

    let response = ReadyResponse::from_health_state(feed_dir, work_dir, true, true, 3);

    assert_eq!(response.status, "ok");
    assert_eq!(response.feed_dir, "/tmp/feed");
    assert_eq!(response.work_dir, "/tmp/work");
    assert!(response.feed_exists);
    assert!(response.work_exists);
    assert_eq!(response.formats_count, 3);
}

#[test]
fn ready_response_from_health_state_returns_not_ready_when_feed_does_not_exist() {
    let feed_dir = PathBuf::from("/tmp/feed");
    let work_dir = PathBuf::from("/tmp/work");

    let response = ReadyResponse::from_health_state(feed_dir, work_dir, false, true, 0);

    assert_eq!(response.status, "not_ready");
    assert_eq!(response.feed_dir, "/tmp/feed");
    assert_eq!(response.work_dir, "/tmp/work");
    assert!(!response.feed_exists);
    assert!(response.work_exists);
    assert_eq!(response.formats_count, 0);
}
