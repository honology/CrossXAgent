use base64::{Engine as _, engine::general_purpose::STANDARD};
use crossx_relay::auth::transcript;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    seed_b64: String,
    principal_hint: String,
    nonce_b64: String,
    cert_digest_b64: String,
    transcript_b64: String,
    signature_b64: String,
}

#[test]
fn transcript_and_signature_match_go_golden_fixture() {
    let fixture: Golden = serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    let seed: [u8; 32] = STANDARD
        .decode(fixture.seed_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = STANDARD.decode(fixture.nonce_b64).unwrap();
    let cert_digest: [u8; 32] = STANDARD
        .decode(fixture.cert_digest_b64)
        .unwrap()
        .try_into()
        .unwrap();

    let actual = transcript(&cert_digest, &fixture.principal_hint, &nonce);
    assert_eq!(STANDARD.encode(&actual), fixture.transcript_b64);

    let signature = SigningKey::from_bytes(&seed).sign(&actual);
    assert_eq!(STANDARD.encode(signature.to_bytes()), fixture.signature_b64);
}
