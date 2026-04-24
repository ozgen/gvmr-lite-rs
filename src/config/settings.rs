use std::{path::PathBuf, str::FromStr};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    None,
    ApiKey,
    Jwt,
}

impl FromStr for AuthMode {
    type Err = config::ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "api_key" => Ok(Self::ApiKey),
            "jwt" => Ok(Self::Jwt),
            other => Err(config::ConfigError::Message(format!(
                "invalid auth_mode '{other}', expected one of: none, api_key, jwt"
            ))),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Settings {
    pub port: u16,
    pub report_formats_feed_dir: PathBuf,
    pub work_dir: PathBuf,

    pub auth_mode: AuthMode,

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

#[derive(Debug, Clone, Deserialize)]
struct RawSettings {
    port: u16,
    report_formats_feed_dir: PathBuf,
    work_dir: PathBuf,

    auth_mode: String,

    api_key: Option<String>,
    api_key_header: String,

    jwt_secret: Option<String>,
    jwt_audience: String,
    jwt_issuer: String,
    jwt_clock_skew_seconds: u64,

    required_scope_render: String,
    required_scope_sync: String,

    rebuild_on_start: bool,

    log_level: String,
    log_format: String,
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

        let raw: RawSettings = config.try_deserialize()?;

        if raw.port == 0 {
            return Err(config::ConfigError::Message(
                "port must be between 1 and 65535".to_string(),
            ));
        }

        Ok(Self {
            port: raw.port,
            report_formats_feed_dir: raw.report_formats_feed_dir,
            work_dir: raw.work_dir,
            auth_mode: AuthMode::from_str(&raw.auth_mode)?,
            api_key: raw.api_key,
            api_key_header: raw.api_key_header,
            jwt_secret: raw.jwt_secret,
            jwt_audience: raw.jwt_audience,
            jwt_issuer: raw.jwt_issuer,
            jwt_clock_skew_seconds: raw.jwt_clock_skew_seconds,
            required_scope_render: raw.required_scope_render,
            required_scope_sync: raw.required_scope_sync,
            rebuild_on_start: raw.rebuild_on_start,
            log_level: raw.log_level,
            log_format: raw.log_format,
        })
    }

    pub fn report_formats_work_dir(&self) -> PathBuf {
        self.work_dir.join("report-formats")
    }
}
