use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArqenorError {
    #[error("platform error: {0}")]
    Platform(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("not supported on this platform")]
    NotSupported,
}
