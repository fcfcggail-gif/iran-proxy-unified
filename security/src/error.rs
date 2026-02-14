use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Obfuscation error: {0}")]
    ObfuscationError(String),

    #[error("Pattern rotation error: {0}")]
    PatternRotationError(String),

    #[error("DPI bypass error: {0}")]
    DPIBypassError(String),

    #[error("Detection evasion error: {0}")]
    DetectionEvadingError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Data error: {0}")]
    DataError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, Error>;
