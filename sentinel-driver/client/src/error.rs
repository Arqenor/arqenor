#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Failed to connect to \\SentinelPort: {0}")]
    ConnectionFailed(#[from] windows::core::Error),

    #[error("Driver not loaded — load sentinel_driver.sys first")]
    DriverNotLoaded,

    #[error("Message receive error: HRESULT {0:#010x}")]
    ReceiveError(u32),

    #[error("Invalid message format")]
    InvalidMessage,
}
