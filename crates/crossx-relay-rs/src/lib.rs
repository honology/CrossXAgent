#![forbid(unsafe_code)]

pub mod auth;
pub mod cert;
pub mod enroll;
pub mod frame;
mod peer;
pub mod protocol;

pub use cert::{Cert, ChainError, RootMap, RootStore, verify_chain};
pub use peer::{Peer, PeerKind, ProxyStream, RelayConfig, RelayPipe};
pub use protocol::ProxyHeader;

use std::io;

/// Failures produced while establishing or using a relay session.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The relay sent an invalid or unsupported protocol message.
    #[error("relay protocol error: {0}")]
    Protocol(String),
    /// Peer identity, role, key, or proof authentication failed.
    #[error("relay peer is unauthenticated")]
    Unauthenticated,
    /// The authenticated principal is not allowed to perform the operation.
    #[error("relay operation is unauthorized")]
    Unauthorized,
    /// No usable live registration exists for the requested target.
    #[error("relay target is offline")]
    TargetOffline,
    /// Another principal owns the target registration.
    #[error("relay registration conflicts with another principal")]
    RegistrationConflict,
    /// The relay and peer do not share protocol version 1.
    #[error("relay protocol version is incompatible")]
    ProtocolVersion,
    /// An underlying socket or stream operation failed.
    #[error("relay I/O error: {0}")]
    Io(#[from] io::Error),
    /// TLS configuration or certificate processing failed.
    #[error("relay TLS error: {0}")]
    Tls(String),
    /// The yamux session failed or closed unexpectedly.
    #[error("relay yamux error: {0}")]
    Yamux(String),
}

impl RelayError {
    /// Converts a protocol-v1 response error code into its typed local error.
    #[must_use]
    pub fn from_wire_code(code: &str) -> Self {
        match code {
            "unauthenticated" => Self::Unauthenticated,
            "unauthorized" => Self::Unauthorized,
            "target_offline" => Self::TargetOffline,
            "registration_conflict" => Self::RegistrationConflict,
            "protocol_version" => Self::ProtocolVersion,
            other => Self::Protocol(other.to_owned()),
        }
    }
}

impl PartialEq for RelayError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Protocol(left), Self::Protocol(right)) => left == right,
            (Self::Unauthenticated, Self::Unauthenticated)
            | (Self::Unauthorized, Self::Unauthorized)
            | (Self::TargetOffline, Self::TargetOffline)
            | (Self::RegistrationConflict, Self::RegistrationConflict)
            | (Self::ProtocolVersion, Self::ProtocolVersion) => true,
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            (Self::Tls(left), Self::Tls(right)) => left == right,
            (Self::Yamux(left), Self::Yamux(right)) => left == right,
            _ => false,
        }
    }
}
