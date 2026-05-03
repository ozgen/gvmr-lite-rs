pub const SPECIAL_KEYS: &[&str] = &["@attrs", "#text"];
pub const FORCE_TEXT_TAGS: &[&str] = &["description", "term"];

pub const REPORT_KEY_ORDER: &[&str] = &[
    "timezone",
    "scan_start",
    "scan_end",
    "task",
    "target",
    "filters",
    "result_count",
    "results",
    "host",
    "hosts",
    "ports",
    "severity",
    "timestamp",
];

pub const RESULT_KEY_ORDER: &[&str] = &[
    "name",
    "owner",
    "modification_time",
    "comment",
    "creation_time",
    "host",
    "port",
    "nvt",
    "scan_nvt_version",
    "threat",
    "severity",
    "qod",
    "description",
    "original_threat",
    "original_severity",
    "compliance",
    "detection",
];

pub const HOST_KEY_ORDER: &[&str] = &[
    "ip",
    "asset",
    "start",
    "end",
    "port_count",
    "result_count",
    "detail",
];
