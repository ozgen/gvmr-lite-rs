use tracing_subscriber::{EnvFilter, fmt};

use crate::config::settings::Settings;

pub fn init(settings: &Settings) {
    let env_filter =
        EnvFilter::try_new(settings.log_level.clone()).unwrap_or_else(|_| EnvFilter::new("info"));

    match settings.log_format.as_str() {
        "json" => {
            fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_current_span(true)
                .with_span_list(true)
                .init();
        }
        _ => {
            fmt()
                .compact()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .init();
        }
    }
}
