use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Network error: {0}")]
    Network(String),
    #[error("MSF-RPC error: {0}")]
    Rpc(String),
    #[error("MSF-RPC module not found: {0}")]
    RpcModuleNotFound(String),
    #[error("msgpack error: {0}")]
    Msgpack(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("SQLite error: {0}")]
    Sqlite(String),
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Sqlite(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
