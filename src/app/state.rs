use crate::{config::settings::Settings, service::format_cache::FormatCache};

#[derive(Debug, Clone)]
pub struct AppState {
    pub settings: Settings,
    pub format_cache: FormatCache,
}

impl AppState {
    pub fn new(settings: Settings, format_cache: FormatCache) -> Self {
        Self {
            settings,
            format_cache,
        }
    }
}