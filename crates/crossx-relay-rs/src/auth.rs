use sha2::{Digest as _, Sha256};

const DOMAIN_TAG: &[u8] = b"crossx-relay/auth/v1";

/// Constructs the exact protocol-v1 Ed25519 authentication transcript.
#[must_use]
pub fn transcript(cert_digest: &[u8; 32], principal: &str, nonce: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        16 + DOMAIN_TAG.len() + cert_digest.len() + principal.len() + nonce.len(),
    );
    append_chunk(&mut output, DOMAIN_TAG);
    append_chunk(&mut output, cert_digest);
    append_chunk(&mut output, principal.as_bytes());
    append_chunk(&mut output, nonce);
    output
}

/// Returns the relay binding used by the authentication transcript.
#[must_use]
pub fn relay_binding(leaf_certificate_der: &[u8]) -> [u8; 32] {
    Sha256::digest(leaf_certificate_der).into()
}

const ENROLL_DOMAIN_TAG: &[u8] = b"crossx-relay/auth/enroll-pop/v1";

/// Constructs the enrolled-peer proof-of-possession transcript. Unlike the
/// bare-identity `transcript`, it binds the FULL signed enrollment via its
/// canonical bytes (project, peer, kind, pubkey, scope, exp), so the proof
/// attests to this exact enrollment. `canonical_claims` must be
/// `enroll::canonical(claims)`. Matches Go `auth.EnrollmentTranscript`.
#[must_use]
pub fn enrollment_transcript(
    cert_digest: &[u8; 32],
    canonical_claims: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        16 + ENROLL_DOMAIN_TAG.len() + cert_digest.len() + canonical_claims.len() + nonce.len(),
    );
    append_chunk(&mut output, ENROLL_DOMAIN_TAG);
    append_chunk(&mut output, cert_digest);
    append_chunk(&mut output, canonical_claims);
    append_chunk(&mut output, nonce);
    output
}

fn append_chunk(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}
