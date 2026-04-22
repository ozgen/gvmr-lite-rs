mod api;
mod app;
mod config;
mod telemetry;

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing::info;

use crate::{
    app::{router::build_router, state::AppState},
    config::settings::Settings,
};

#[tokio::main]
async fn main() {
    let settings = Settings::load().expect("failed to load settings");
    telemetry::init(&settings);

    info!(
        port = settings.port,
        auth_mode = %settings.auth_mode,
        report_formats_feed_dir = %settings.report_formats_feed_dir.display(),
        work_dir = %settings.work_dir.display(),
        rebuild_on_start = settings.rebuild_on_start,
        log_level = %settings.log_level,
        log_format = %settings.log_format,
        "settings loaded"
    );

    let app_state = AppState::new(settings.clone());
    let app = build_router().with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], settings.port));
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    info!(bind_address = %addr, "tcp listener bound");
    info!("starting HTTP server");

    axum::serve(listener, app)
        .await
        .expect("server error");
}