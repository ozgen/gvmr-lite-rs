pub mod api;
pub mod app;
pub mod auth;
pub mod openapi;
pub mod telemetry;

use std::net::SocketAddr;

use config::settings::Settings;
use gvmr_core::service::format_cache::FormatCache;
use tokio::net::TcpListener;
use tracing::{Instrument, info};

use crate::app::{error::AppError, router::build_router, state::AppState};

pub async fn run() -> Result<(), AppError> {
    let settings = Settings::load()?;

    telemetry::init(&settings);

    let service_span = tracing::info_span!(
        "service",
        service = "gvmr-server",
        version = env!("CARGO_PKG_VERSION"),
    );

    async move {
        let app_state = build_app_state(settings.clone())?;
        let app = build_router(app_state);

        let listener = bind_listener(settings.port).await?;

        info!("starting HTTP server");

        axum::serve(listener, app).await.map_err(AppError::Server)?;

        Ok(())
    }
    .instrument(service_span)
    .await
}

pub(crate) fn build_app_state(settings: Settings) -> Result<AppState, AppError> {
    info!(
        port = settings.port,
        auth_mode = ?settings.auth_mode,
        report_formats_feed_dir = %settings.report_formats_feed_dir.display(),
        work_dir = %settings.work_dir.display(),
        rebuild_on_start = settings.rebuild_on_start,
        log_level = %settings.log_level,
        log_format = %settings.log_format,
        "settings loaded"
    );

    let mut format_cache = FormatCache::new(
        settings.report_formats_feed_dir.clone(),
        settings.report_formats_work_dir(),
        settings.rebuild_on_start,
        settings.experimental_enabled,
    );

    format_cache.initialize().map_err(AppError::Bind)?;

    info!(
        formats_count = format_cache.list().len(),
        audit_format_count = format_cache.list_audit().len(),
        "format cache initialized"
    );

    Ok(AppState::new(settings, format_cache))
}

pub(crate) async fn bind_listener(port: u16) -> Result<TcpListener, AppError> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!(bind_address = %addr, "tcp listener bound");

    TcpListener::bind(addr).await.map_err(AppError::Server)
}

pub mod config;
#[cfg(test)]
#[path = "lib_tests.rs"]
mod lib_tests;
