use super::env_filter_from;

#[test]
fn env_filter_from_accepts_valid_log_level() {
    let filter = env_filter_from("debug");

    assert_eq!(filter.to_string(), "debug");
}

#[test]
fn env_filter_from_falls_back_to_info_for_invalid_log_level() {
    let filter = env_filter_from("gvmr_lite_rs=notalevel");

    assert_eq!(filter.to_string(), "info");
}
