use std::path::PathBuf;

use serde::Deserialize;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub port: u16,
    pub report_formats_feed_dir: PathBuf,
    pub work_dir: PathBuf,

    pub auth_mode: String,

    pub api_key: Option<String>,
    pub api_key_header: String,

    pub jwt_secret: Option<String>,
    pub jwt_audience: String,
    pub jwt_issuer: String,
    pub jwt_clock_skew_seconds: u64,

    pub required_scope_render: String,
    pub required_scope_sync: String,

    pub rebuild_on_start: bool,

    pub log_level: String,
    pub log_format: String,
}

impl Settings {
    pub fn load() -> Result<Self, config::ConfigError> {
        let _ = dotenvy::dotenv();

        let config = config::Config::builder()
            .set_default("port", 8084)?
            .set_default(
                "report_formats_feed_dir",
                "/var/lib/gvm/data-objects/gvmd/report-formats",
            )?
            .set_default("work_dir", "/tmp/gvmr-lite/work")?
            .set_default("auth_mode", "none")?
            .set_default("api_key_header", "X-API-Key")?
            .set_default("jwt_audience", "gvmr-lite")?
            .set_default("jwt_issuer", "gvmd-lite")?
            .set_default("jwt_clock_skew_seconds", 300)?
            .set_default("required_scope_render", "render")?
            .set_default("required_scope_sync", "sync")?
            .set_default("rebuild_on_start", true)?
            .set_default("log_level", "info")?
            .set_default("log_format", "pretty")?
            .add_source(config::Environment::with_prefix("GVMR"))
            .build()?;

        let settings: Settings = config.try_deserialize()?;

        if settings.port == 0 {
            return Err(config::ConfigError::Message(
                "port must be between 1 and 65535".to_string(),
            ));
        }

        Ok(settings)
    }

    pub fn report_formats_work_dir(&self) -> PathBuf {
        self.work_dir.join("report-formats")
    }
}