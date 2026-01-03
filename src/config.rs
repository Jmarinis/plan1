use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub discovery_port: u16,
    pub communication_port: u16,
    pub bind_host: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string("config.toml")?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Config {
            network: NetworkConfig {
                discovery_port: 39000,
                communication_port: 39001,
                bind_host: "".to_string(),
            },
            security: SecurityConfig {
                cert_path: "certs/server_cert.pem".to_string(),
                key_path: "certs/server_key.pem".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
        }
    }
}