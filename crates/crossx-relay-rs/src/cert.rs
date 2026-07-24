//! The crossx-relay certificate chain-to-root. A peer presents a
//! `[member, org, issuing]` chain that the relay validates offline up to a
//! trusted root. `canonical_cert` is the NORMATIVE cross-language interop
//! surface — it reproduces the Go `enroll.CanonicalCert` (crossx-relay repo,
//! `enroll/cert.go`) byte-for-byte, and the `cert_golden` conformance test pins
//! that against Go `devmaterial` output.

use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::enroll::{self, Claims, Token};

/// Domain-separation tag / format version for the certificate canonical bytes.
const TAG: &[u8] = b"crossx-relay/cert/v1";

/// Chain roles, leaf to trust anchor. Wire values match Go `enroll.Role`.
pub const ROLE_ISSUING: &str = "issuing";
pub const ROLE_ORG: &str = "org";
pub const ROLE_MEMBER: &str = "member";

/// One link in the chain-to-root: an issuer's signature binding a subject public
/// key to a role and (for org/member) an org namespace, with an expiry. Compact,
/// non-X.509. Field order and JSON names mirror Go `enroll.Cert` exactly.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cert {
    #[serde(rename = "subject_pub", with = "base64_bytes")]
    pub subject_pub: Vec<u8>,
    pub subject_id: String,
    pub role: String,
    pub org_namespace: String,
    pub exp: i64,
    pub issuer_id: String,
    #[serde(with = "base64_bytes")]
    pub sig: Vec<u8>,
}

fn append_chunk(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

/// Produces the deterministic byte layout the issuer signs. MUST stay
/// byte-identical to Go `enroll.CanonicalCert`. `exp` is encoded as the 8-byte
/// big-endian of `uint64(exp)` (identical bytes to `i64::to_be_bytes` here).
#[must_use]
pub fn canonical_cert(cert: &Cert) -> Vec<u8> {
    let mut out = Vec::new();
    append_chunk(&mut out, TAG);
    append_chunk(&mut out, &cert.subject_pub);
    append_chunk(&mut out, cert.subject_id.as_bytes());
    append_chunk(&mut out, cert.role.as_bytes());
    append_chunk(&mut out, cert.org_namespace.as_bytes());
    append_chunk(&mut out, &(cert.exp as u64).to_be_bytes());
    append_chunk(&mut out, cert.issuer_id.as_bytes());
    out
}

/// Reports whether `cert.sig` is a valid signature by `issuer_pub` over
/// `canonical_cert(cert)`. Returns `false` (never panics) on a wrong-length key
/// or signature, mirroring the Go `verifyCertSig` length guards.
#[must_use]
pub fn verify_cert_sig(cert: &Cert, issuer_pub: &[u8]) -> bool {
    let Ok(pub_bytes): Result<[u8; 32], _> = issuer_pub.try_into() else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pub_bytes) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = cert.sig.as_slice().try_into() else {
        return false;
    };
    verifying
        .verify_strict(&canonical_cert(cert), &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// Resolves a root ID to its trusted public key.
pub trait RootStore {
    fn root(&self, id: &str) -> Option<[u8; 32]>;
}

/// In-memory `RootStore` mapping a root ID to its trusted public key.
#[derive(Debug, Default, Clone)]
pub struct RootMap(HashMap<String, [u8; 32]>);

impl RootMap {
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, id: impl Into<String>, pub_key: [u8; 32]) {
        self.0.insert(id.into(), pub_key);
    }
}

impl RootStore for RootMap {
    fn root(&self, id: &str) -> Option<[u8; 32]> {
        self.0.get(id).copied()
    }
}

/// Chain-validation failures. Variants mirror the Go `enroll` sentinels; `Enroll`
/// is the member-signed-enrollment failure (`enroll.Verify` in Go).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("invalid certificate chain")]
    Chain,
    #[error("issuing cert not signed by a trusted root")]
    UntrustedRoot,
    #[error("expired")]
    Expired,
    #[error("project outside org namespace")]
    CrossOrg,
    #[error("enrollment signature is invalid")]
    Enroll,
}

/// Validates a `[member, org, issuing]` chain plus the member-signed enrollment,
/// returning the trusted claims. Reproduces Go `enroll.VerifyChain`. It does NOT
/// perform the proof-of-possession — the caller verifies that against
/// `claims.pub`. `now_unix` is the verifier's clock (seconds).
pub fn verify_chain(
    token: &Token,
    chain: &[Cert],
    roots: &impl RootStore,
    now_unix: i64,
) -> Result<Claims, ChainError> {
    let [member, org, issuing] = chain else {
        return Err(ChainError::Chain);
    };
    if member.role != ROLE_MEMBER || org.role != ROLE_ORG || issuing.role != ROLE_ISSUING {
        return Err(ChainError::Chain);
    }
    for cert in chain {
        if cert.exp <= 0 || now_unix >= cert.exp {
            return Err(ChainError::Expired);
        }
    }
    if !verify_cert_sig(member, &org.subject_pub) || !verify_cert_sig(org, &issuing.subject_pub) {
        return Err(ChainError::Chain);
    }
    let root_pub = roots
        .root(&issuing.issuer_id)
        .ok_or(ChainError::UntrustedRoot)?;
    if !verify_cert_sig(issuing, &root_pub) {
        return Err(ChainError::UntrustedRoot);
    }
    if member.org_namespace.is_empty() || member.org_namespace != org.org_namespace {
        return Err(ChainError::Chain);
    }
    let member_pub: [u8; 32] = member
        .subject_pub
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::Chain)?;
    let claims = enroll::verify(token, &member_pub).map_err(|_| ChainError::Enroll)?;
    if claims.exp <= 0 || now_unix >= claims.exp {
        return Err(ChainError::Expired);
    }
    if !within(&claims.project, &member.org_namespace) {
        return Err(ChainError::CrossOrg);
    }
    Ok(claims)
}

/// Reports whether `project` is exactly `ns` or a path strictly below it. Both
/// must be clean paths (no empty, `.`, or `..` segments). Matches Go `within`.
fn within(project: &str, ns: &str) -> bool {
    if !clean_path(project) || !clean_path(ns) {
        return false;
    }
    project == ns || project.starts_with(&format!("{ns}/"))
}

/// Reports whether `s` is non-empty and has no empty, `.`, or `..` segment.
fn clean_path(s: &str) -> bool {
    !s.is_empty()
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signed(subject: &SigningKey, issuer: &SigningKey, role: &str, ns: &str) -> Cert {
        let mut cert = Cert {
            subject_pub: subject.verifying_key().to_bytes().to_vec(),
            subject_id: "s".to_owned(),
            role: role.to_owned(),
            org_namespace: ns.to_owned(),
            exp: 4_102_444_800,
            issuer_id: "i".to_owned(),
            sig: Vec::new(),
        };
        cert.sig = issuer.sign(&canonical_cert(&cert)).to_bytes().to_vec();
        cert
    }

    #[test]
    fn verify_cert_sig_accepts_honest_signature_and_rejects_tampering() {
        let issuer = SigningKey::from_bytes(&[1_u8; 32]);
        let subject = SigningKey::from_bytes(&[2_u8; 32]);
        let issuer_pub = issuer.verifying_key().to_bytes();

        let cert = signed(&subject, &issuer, ROLE_MEMBER, "orgA");
        assert!(verify_cert_sig(&cert, &issuer_pub));

        // Any post-signing field edit invalidates the signature.
        let mut tampered = cert.clone();
        tampered.org_namespace = "orgB".to_owned();
        assert!(!verify_cert_sig(&tampered, &issuer_pub));

        // Wrong issuer key rejects.
        let other = SigningKey::from_bytes(&[3_u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(!verify_cert_sig(&cert, &other));

        // Malformed issuer key / signature length reject without panic.
        assert!(!verify_cert_sig(&cert, &[0_u8; 31]));
        let mut bad_sig = cert.clone();
        bad_sig.sig.truncate(63);
        assert!(!verify_cert_sig(&bad_sig, &issuer_pub));
    }
}
