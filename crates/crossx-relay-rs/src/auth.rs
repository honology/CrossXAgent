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

fn append_chunk(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}
