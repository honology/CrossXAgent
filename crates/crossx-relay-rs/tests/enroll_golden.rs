//! Cross-language conformance: the Rust `enroll::canonical` and verification must
//! agree byte-for-byte with the Go `enroll` package. Fixtures are produced by the
//! Go `cmd/devmaterial` (`enrollment.json` + `enrollment-canonical.b64` +
//! `authority.ed25519` seed) and committed under `tests/fixtures/`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crossx_relay::enroll::{self, Token};
use ed25519_dalek::SigningKey;

fn golden_token() -> Token {
    serde_json::from_str(include_str!("fixtures/enroll_golden_enrollment.json"))
        .expect("golden enrollment.json parses")
}

fn authority_pub() -> [u8; 32] {
    let seed_b64 = include_str!("fixtures/enroll_golden_authority.seed").trim();
    let seed: [u8; 32] = STANDARD
        .decode(seed_b64)
        .expect("authority seed is base64")
        .try_into()
        .expect("authority seed is 32 bytes");
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

#[test]
fn canonical_matches_go_golden_byte_for_byte() {
    let token = golden_token();
    let golden_b64 = include_str!("fixtures/enroll_golden_canonical.b64").trim();
    let actual = enroll::canonical(&token.claims);
    assert_eq!(
        STANDARD.encode(&actual),
        golden_b64,
        "Rust enroll::canonical diverged from Go enroll.Canonical"
    );
}

#[test]
fn verify_accepts_go_signed_enrollment() {
    let token = golden_token();
    let claims = enroll::verify(&token, &authority_pub()).expect("Go-signed enrollment verifies");
    assert_eq!(claims.project, "proj-e2e");
    assert_eq!(claims.peer, "agent-e2e");
    assert_eq!(claims.kind, "agent");
    assert_eq!(claims.v, enroll::V1);
    assert_eq!(claims.scope, vec!["e2e-node".to_owned()]);
}

#[test]
fn verify_rejects_tampered_claims() {
    let mut token = golden_token();
    token.claims.scope.push("vm-smuggled".to_owned()); // any post-signing edit invalidates
    assert_eq!(
        enroll::verify(&token, &authority_pub()),
        Err(enroll::EnrollError::InvalidSignature)
    );
}

#[test]
fn verify_rejects_wrong_authority() {
    let token = golden_token();
    let other = SigningKey::from_bytes(&[7_u8; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        enroll::verify(&token, &other),
        Err(enroll::EnrollError::InvalidSignature)
    );
}

#[test]
fn parsing_rejects_unknown_fields() {
    // Matches the Go relay's strict decoder (DisallowUnknownFields): a stray field
    // must fail to parse locally, so a malformed enrollment file is rejected up
    // front rather than silently entering a doomed reconnect loop.
    let unknown_claims_field = r#"{"claims":{"v":1,"project":"p","peer":"a","kind":"agent","pub":"AAAA","scope":["x"],"exp":1,"typo":"oops"},"sig":"AAAA"}"#;
    assert!(serde_json::from_str::<Token>(unknown_claims_field).is_err());
    let unknown_token_field = r#"{"claims":{"v":1,"project":"p","peer":"a","kind":"agent","pub":"AAAA","scope":["x"],"exp":1},"sig":"AAAA","extra":1}"#;
    assert!(serde_json::from_str::<Token>(unknown_token_field).is_err());
}
