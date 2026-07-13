//! The crossx-relay enrollment credential: a control-plane-signed set of claims
//! a peer presents to the relay. Its canonical encoding is the NORMATIVE
//! cross-language interop surface — this module reproduces the Go
//! `enroll.Canonical` byte-for-byte (crossx-relay repo, `enroll/enroll.go`). The
//! `enroll_golden` conformance test pins that against Go `devmaterial` output.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain-separation tag / format version for the enrollment canonical bytes.
const TAG: &[u8] = b"crossx-relay/enroll/v1";

/// Current enrollment claims version. Verifiers reject any other value.
pub const V1: u16 = 1;

/// The signed fields of an enrollment. `pub_key` is the peer's Ed25519 identity
/// public key; `exp` is a Unix timestamp (seconds); `scope` is a list of bare
/// targetIDs (namespaced by `project` on the relay).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Claims {
    pub v: u16,
    pub project: String,
    pub peer: String,
    pub kind: String,
    #[serde(rename = "pub", with = "base64_bytes")]
    pub pub_key: Vec<u8>,
    pub scope: Vec<String>,
    pub exp: i64,
}

/// A signed enrollment: the claims plus a detached Ed25519 signature over
/// `canonical(claims)`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    pub claims: Claims,
    #[serde(with = "base64_bytes")]
    pub sig: Vec<u8>,
}

/// Failures verifying an enrollment.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollError {
    /// The signature did not verify against the authority key.
    #[error("enrollment signature is invalid")]
    InvalidSignature,
    /// The authority public key or the signature had the wrong length/shape.
    #[error("enrollment public key or signature is malformed")]
    Malformed,
}

fn append_chunk(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

/// Produces the deterministic byte layout that is signed and verified. The scope
/// targetIDs are sorted so the encoding is independent of input order. This MUST
/// stay byte-identical to Go `enroll.Canonical`.
#[must_use]
pub fn canonical(claims: &Claims) -> Vec<u8> {
    let mut scope: Vec<&str> = claims.scope.iter().map(String::as_str).collect();
    scope.sort_unstable(); // byte-wise lexical, matching Go sort.Strings

    // scope block: u32_be(count) ∥ chunk(t_i)...
    let mut scope_block = Vec::new();
    let count = u32::try_from(scope.len()).unwrap_or(u32::MAX);
    scope_block.extend_from_slice(&count.to_be_bytes());
    for target in &scope {
        append_chunk(&mut scope_block, target.as_bytes());
    }

    let mut out = Vec::new();
    append_chunk(&mut out, TAG);
    append_chunk(&mut out, &claims.v.to_be_bytes());
    append_chunk(&mut out, claims.project.as_bytes());
    append_chunk(&mut out, claims.peer.as_bytes());
    append_chunk(&mut out, claims.kind.as_bytes());
    append_chunk(&mut out, &claims.pub_key);
    append_chunk(&mut out, &scope_block);
    append_chunk(&mut out, &claims.exp.to_be_bytes());
    out
}

/// Verifies the token's signature against the authority public key and returns
/// the claims. It does NOT check `exp` — the caller does, with its own clock.
pub fn verify(token: &Token, authority_pub: &[u8; 32]) -> Result<Claims, EnrollError> {
    let verifying = VerifyingKey::from_bytes(authority_pub).map_err(|_| EnrollError::Malformed)?;
    let sig_bytes: [u8; 64] = token
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| EnrollError::Malformed)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying
        .verify_strict(&canonical(&token.claims), &signature)
        .map_err(|_| EnrollError::InvalidSignature)?;
    Ok(token.claims.clone())
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
