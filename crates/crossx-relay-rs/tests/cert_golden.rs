//! Cross-language conformance: Rust `verify_chain` must accept the Go
//! `devmaterial` golden `[member, org, issuing]` chain against its `roots.json`.
//! Because `verify_cert_sig` recomputes `canonical_cert` and checks the Go-made
//! signature, a passing run also proves `canonical_cert` is byte-identical to Go
//! `enroll.CanonicalCert`. Fixtures are produced by Go `cmd/devmaterial`.

use crossx_relay::cert::{Cert, RootMap, verify_chain};
use crossx_relay::enroll::Token;
use serde::Deserialize;

const NOW: i64 = 1_800_000_000; // ~2027, within the fixtures' validity window

#[derive(Deserialize)]
struct RootsFile {
    roots: Vec<RootRec>,
}

#[derive(Deserialize)]
struct RootRec {
    id: String,
    #[serde(rename = "pub")]
    pub_b64: String,
}

fn golden_roots() -> RootMap {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let file: RootsFile =
        serde_json::from_str(include_str!("fixtures/cert_golden_roots.json")).expect("roots.json");
    let mut roots = RootMap::new();
    for rec in file.roots {
        let key: [u8; 32] = STANDARD
            .decode(&rec.pub_b64)
            .expect("root pub base64")
            .try_into()
            .expect("root pub is 32 bytes");
        roots.add(rec.id, key);
    }
    roots
}

#[test]
fn verify_chain_accepts_go_golden_chain() {
    let chain: Vec<Cert> =
        serde_json::from_str(include_str!("fixtures/cert_golden_chain.json")).expect("chain.json");
    let token: Token = serde_json::from_str(include_str!("fixtures/enroll_golden_enrollment.json"))
        .expect("enrollment.json");
    let claims =
        verify_chain(&token, &chain, &golden_roots(), NOW).expect("Go golden chain verifies");
    assert_eq!(claims.project, "proj-e2e");
    assert_eq!(claims.peer, "agent-e2e");
    assert_eq!(claims.kind, "agent");
}

#[test]
fn verify_chain_rejects_go_golden_under_empty_roots() {
    let chain: Vec<Cert> =
        serde_json::from_str(include_str!("fixtures/cert_golden_chain.json")).expect("chain.json");
    let token: Token = serde_json::from_str(include_str!("fixtures/enroll_golden_enrollment.json"))
        .expect("enrollment.json");
    assert_eq!(
        verify_chain(&token, &chain, &RootMap::new(), NOW),
        Err(crossx_relay::cert::ChainError::UntrustedRoot)
    );
}
