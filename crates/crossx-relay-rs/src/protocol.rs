use serde::{Deserialize, Serialize};

/// Protocol version implemented by this crate.
pub const VERSION: u16 = 1;

/// Initial authentication role and version offer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthInit {
    /// Supported protocol versions, newest first.
    pub versions: Vec<u16>,
    /// Claimed peer role (`agent` or `desktop`).
    pub kind: String,
    /// Registered public-key record identifier (M0) or the enrollment's peer (M1).
    pub principal_hint: String,
    /// Signed enrollment token for the M1 enrollment-auth path; omitted (and not
    /// serialized) on the M0 pubkey path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<crate::enroll::Token>,
}

/// Relay authentication challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Challenge {
    /// Fresh challenge nonce.
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
}

/// Signed authentication proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthProof {
    /// Ed25519 signature over the protocol-v1 transcript.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// Authentication result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthResp {
    /// Opaque session identifier, present on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Selected protocol version, present on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u16>,
    /// Protocol error code, absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Agent target registration request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Register {
    /// Target made reachable through this registration.
    pub target_id: String,
    /// L4 protocol served by the target.
    pub proto: String,
}

/// Agent registration result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterResp {
    /// Opaque token returned after successful registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_token: Option<String>,
    /// Protocol error code, absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Desktop tunnel request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Dial {
    /// Registered target identifier.
    pub target_id: String,
    /// Requested L4 protocol.
    pub proto: String,
    /// Agent-local service port.
    pub port: u16,
}

/// Desktop tunnel result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DialResp {
    /// Protocol error code, absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Relay metadata that begins an agent-side proxy stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyHeader {
    /// Opaque brokered-tunnel identifier.
    pub tunnel_id: String,
    /// L4 protocol copied from the desktop request.
    pub proto: String,
    /// Agent-local port copied from the desktop request.
    pub port: u16,
    /// Desktop stream address observed by the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = <String>::deserialize(deserializer)?;
        STANDARD.decode(encoded).map_err(D::Error::custom)
    }
}
