use std::env;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Result;

fn home_dir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home)
    } else if let Some(profile) = env::var_os("USERPROFILE") {
        PathBuf::from(profile)
    } else {
        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }
}

pub fn config_dir() -> PathBuf {
    home_dir().join(".config").join("ploit_malper")
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.json")
}

pub fn nvd_cache_file() -> PathBuf {
    config_dir().join("nvd_cache.json")
}

pub fn db_schema_file() -> PathBuf {
    config_dir().join("schema.pbsl")
}

pub fn default_sqlite_db() -> PathBuf {
    config_dir().join("ploit_malper.db")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MSFRPCConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub ssl: bool,
    pub workspace: String,
}

impl Default for MSFRPCConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 55553,
            username: "msf".to_string(),
            password: String::new(),
            ssl: true,
            workspace: "default".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NVDConfig {
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Which storage backend is active: "pocketbase" or "sqlite".
    pub backend: String,
    /// PocketBase instance URL (local or remote/shared).
    pub pocketbase_url: String,
    /// Auth token used to talk to the PocketBase API. May be empty if only
    /// admin credentials are stored and a fresh token must be minted.
    pub pocketbase_token: String,
    /// Superuser / admin email for authenticating to PocketBase.
    pub pocketbase_admin_email: String,
    /// Superuser / admin password for authenticating to PocketBase.
    pub pocketbase_admin_password: String,
    /// Local SQLite database file path.
    pub sqlite_path: String,
    /// Whether a database has been configured through `db_setup`.
    pub configured: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            backend: "pocketbase".to_string(),
            pocketbase_url: "http://127.0.0.1:8090".to_string(),
            pocketbase_token: String::new(),
            pocketbase_admin_email: String::new(),
            pocketbase_admin_password: String::new(),
            sqlite_path: default_sqlite_db().to_string_lossy().to_string(),
            configured: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub msfrpc: MSFRPCConfig,
    pub nvd: NVDConfig,
    pub database: DatabaseConfig,
    pub report_dir: String,
    pub last_scan_file: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            msfrpc: MSFRPCConfig::default(),
            nvd: NVDConfig::default(),
            database: DatabaseConfig::default(),
            report_dir: home_dir()
                .join("ploit_malper_reports")
                .to_string_lossy()
                .to_string(),
            last_scan_file: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigManager {
    pub config: AppConfig,
    loaded: bool,
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            config: AppConfig::default(),
            loaded: false,
        }
    }

    pub fn load(&mut self) -> bool {
        let path = config_file();
        if !path.exists() {
            return false;
        }

        match fs::read_to_string(&path) {
            Ok(raw) => match serde_json::from_str::<AppConfig>(&raw) {
                Ok(config) => {
                    self.config = config;
                    self.loaded = true;
                    true
                }
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    pub fn save(&mut self) -> Result<()> {
        let dir = config_dir();
        fs::create_dir_all(&dir)?;
        let path = config_file();
        let data = serde_json::to_string_pretty(&self.config)?;
        fs::write(path, data)?;
        self.loaded = true;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        let config_path = config_file();
        if config_path.exists() {
            fs::remove_file(config_path)?;
        }

        let cache_path = nvd_cache_file();
        if cache_path.exists() {
            fs::remove_file(cache_path)?;
        }

        self.config = AppConfig::default();
        self.loaded = false;
        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        self.loaded && !self.config.msfrpc.password.is_empty()
    }

    pub fn is_nvd_configured(&self) -> bool {
        !self.config.nvd.api_key.is_empty()
    }

    pub fn get_msfrpc_config(&self) -> &MSFRPCConfig {
        &self.config.msfrpc
    }

    pub fn get_nvd_config(&self) -> &NVDConfig {
        &self.config.nvd
    }

    pub fn get_database_config(&self) -> &DatabaseConfig {
        &self.config.database
    }

    pub fn database_configured(&self) -> bool {
        self.config.database.configured
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}
