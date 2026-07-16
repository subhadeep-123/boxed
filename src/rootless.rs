pub struct RootlessConfig {
    pub enabled: bool,
}

impl RootlessConfig {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}
