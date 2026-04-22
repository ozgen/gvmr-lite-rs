use crate::config::settings::Settings;

#[derive(Debug, Clone)]
pub struct AppState {
    pub settings: Settings,
}

impl AppState {
    pub fn new(settings: Settings) -> Self {
        Self { settings }
    }
}