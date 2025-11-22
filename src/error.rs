use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MockServerError {
    #[error("Failed to bind to address {addr}: {source}")]
    BindError {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("Server task panicked")]
    ServerPanic(#[from] tokio::task::JoinError),

    #[error("Failed to parse protobuf request: {0}")]
    ProtobufParseError(#[from] prost::DecodeError),

    #[error("Failed to parse JSON request: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("Failed to encode response: {0}")]
    EncodeError(String),

    #[error("Server error: {0}")]
    ServerError(String),
}
