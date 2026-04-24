mod api;
mod app;
mod auth;
mod config;
mod domain;
mod service;
mod telemetry;

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing::info;

use crate::{
    app::{router::build_router, state::AppState},
    config::settings::Settings,
    service::format_cache::FormatCache,
};

#[tokio::main]
async fn main() {
    let settings = Settings::load().expect("failed to load settings");
    telemetry::init(&settings);

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
    );

    format_cache
        .initialize()
        .expect("failed to initialize format cache");

    info!(
        formats_count = format_cache.list().len(),
        "format cache initialized"
    );

    let app_state = AppState::new(settings.clone(), format_cache);
    let app = build_router(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], settings.port));
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    info!(bind_address = %addr, "tcp listener bound");
    info!("starting HTTP server");

    axum::serve(listener, app).await.expect("server error");
}
