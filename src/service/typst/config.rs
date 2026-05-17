#[derive(Debug, Clone)]
pub struct TypstChunkingConfig {
    pub enabled: bool,
    pub threshold_results: usize,
    pub max_results_per_chunk: usize,
    pub max_parallel_chunks: usize,
}

impl Default for TypstChunkingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_results: 500,
            max_results_per_chunk: 200,
            max_parallel_chunks: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypstProcessLimits {
    pub enabled: bool,
    pub use_user_scope: bool,
    pub memory_max: String,
    pub cpu_quota: String,
    pub tasks_max: u32,
}

impl Default for TypstProcessLimits {
    fn default() -> Self {
        Self {
            enabled: true,
            use_user_scope: true,
            memory_max: "2G".to_string(),
            cpu_quota: "150%".to_string(),
            tasks_max: 64,
        }
    }
}

impl TypstProcessLimits {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            use_user_scope: false,
            memory_max: String::new(),
            cpu_quota: String::new(),
            tasks_max: 0,
        }
    }
}
