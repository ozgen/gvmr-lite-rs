use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{config::settings::Settings, service::format_cache_service::FormatCache};

#[derive(Debug, Clone)]
pub struct AppState {
    pub settings: Settings,
    pub format_cache: Arc<RwLock<FormatCache>>, // /sync will mutate FormatCache, AppState should hold it behind a lock.
}

impl AppState {
    pub fn new(settings: Settings, format_cache: FormatCache) -> Self {
        Self {
            settings,
            format_cache: Arc::new(RwLock::new(format_cache)),
        }
    }
}
