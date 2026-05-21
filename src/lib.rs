pub mod api;
pub mod app;
pub mod auth;
pub mod cli;
pub mod cli_render;
pub mod config;
pub mod domain;
pub mod infra;
pub mod openapi;
pub mod service;
pub mod telemetry;
pub mod xml;

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing::info;

use crate::{
    app::{error::AppError, router::build_router, state::AppState},
    cli::Cli,
    cli_render::render_xml_file,
    config::settings::Settings,
    service::format_cache::FormatCache,
};

pub async fn run_cli_or_server(cli: Cli) -> Result<(), AppError> {
    cli.validate().map_err(AppError::Config)?;

    if cli.is_render_mode() {
        let xml_path = cli.xml.as_ref().expect("validated cli xml path");
        let renderer_type = cli.renderer_type.expect("validated cli renderer type");
        let output_path = cli.output_path();

        render_xml_file(renderer_type, xml_path, &output_path)?;

        return Ok(());
    }

    run().await
}

pub async fn run() -> Result<(), AppError> {
    let settings = Settings::load()?;
    telemetry::init(&settings);

    let app_state = build_app_state(settings.clone())?;
    let app = build_router(app_state);

    let listener = bind_listener(settings.port).await?;

    info!("starting HTTP server");

    axum::serve(listener, app).await.map_err(AppError::Server)?;

    Ok(())
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
        "format cache initialized"
    );

    Ok(AppState::new(settings, format_cache))
}

pub(crate) async fn bind_listener(port: u16) -> Result<TcpListener, AppError> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(bind_address = %addr, "tcp listener bound");
    TcpListener::bind(addr).await.map_err(AppError::Server)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod lib_tests;
