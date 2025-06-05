// src/config.rs
use serde::Deserialize;

fn default_server_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_server_port() -> u16 {
    8080
}

// Helper function for default log level
fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_server_addr", alias = "HTTP_HOST")]
    pub http_host: String,
    #[serde(default = "default_server_port", alias = "HTTP_PORT")]
    pub http_port: u16,
    #[serde(default = "default_log_level", alias = "LOG_LEVEL")]
    pub log_level: String, // e.g., "debug", "info", "warn", "error"
    #[serde(alias = "DATABASE_URL")]
    pub database_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        dotenvy::dotenv().ok();

        let builder =
            config::Config::builder().add_source(config::Environment::default().try_parsing(true));

        let config = builder.build()?;
        config.try_deserialize()
    }
}
