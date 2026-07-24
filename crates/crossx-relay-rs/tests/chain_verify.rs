//! `verify_chain` reject/accept matrix — the Rust twin of the Go
//! `enroll/chain_test.go` mutation-killers. Each test pins one trust-anchor
//! check so a regression is caught, not silently accepted.

mod common;

use common::{DevCa, enroll_token, sign_cert_pub};
use crossx_relay::cert::{Cert, ChainError, RootMap, verify_chain};
use ed25519_dalek::SigningKey;

const FUTURE: i64 = 4_102_444_800; // 2100-01-01Z
const NOW: i64 = 1_800_000_000; // ~2027, within [gen, FUTURE)

fn ca_and_roots() -> (DevCa, RootMap) {
    let ca = DevCa::new(FUTURE);
    let mut roots = RootMap::new();
    roots.add(ca.root_id.clone(), ca.root_pub);
    (ca, roots)
}

// Well-formed agent chain + a fresh PoP key + a member-signed enrollment.
fn valid(ca: &DevCa, project: &str) -> (Vec<Cert>, crossx_relay::enroll::Token) {
    let (chain, member) = ca.member("orgA", "member-1", 20, 21);
    let pop = SigningKey::from_bytes(&[22_u8; 32]);
    let token = enroll_token(&member, &pop, project, "peer-1", "agent", &["vm1"], FUTURE);
    (chain, token)
}

#[test]
fn accepts_well_formed_chain() {
    let (ca, roots) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgA/prod");
    let claims = verify_chain(&token, &chain, &roots, NOW).expect("valid chain accepted");
    assert_eq!(claims.project, "orgA/prod");
}

#[test]
fn rejects_cross_org() {
    let (ca, roots) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgB/prod");
    assert_eq!(
        verify_chain(&token, &chain, &roots, NOW),
        Err(ChainError::CrossOrg)
    );
}

#[test]
fn rejects_unsafe_project() {
    let (ca, roots) = ca_and_roots();
    for project in ["orgA/../orgB", "orgA/", "orgA//x", "orgA/./x", "orgA/.."] {
        let (chain, token) = valid(&ca, project);
        assert_eq!(
            verify_chain(&token, &chain, &roots, NOW),
            Err(ChainError::CrossOrg),
            "project {project} must be rejected"
        );
    }
}

#[test]
fn rejects_untrusted_root() {
    let (ca, _) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgA/prod");
    assert_eq!(
        verify_chain(&token, &chain, &RootMap::new(), NOW),
        Err(ChainError::UntrustedRoot)
    );
}

#[test]
fn rejects_forged_issuing_cert() {
    // Re-sign the issuing cert (trusted root id, same subject key) with a key the
    // root never certified. Pins the root SIGNATURE check, not just the id lookup.
    let (ca, roots) = ca_and_roots();
    let (mut chain, token) = valid(&ca, "orgA/prod");
    let attacker = SigningKey::from_bytes(&[99_u8; 32]);
    chain[2] = sign_cert_pub(chain[2].clone(), &attacker);
    assert_eq!(
        verify_chain(&token, &chain, &roots, NOW),
        Err(ChainError::UntrustedRoot)
    );
}

#[test]
fn rejects_tampered_member_and_org() {
    let (ca, roots) = ca_and_roots();
    for idx in [0_usize, 1] {
        let (mut chain, token) = valid(&ca, "orgA/prod");
        chain[idx].sig[0] ^= 0xff;
        assert_eq!(
            verify_chain(&token, &chain, &roots, NOW),
            Err(ChainError::Chain),
            "tampered chain[{idx}] must be rejected"
        );
    }
}

#[test]
fn rejects_namespace_mismatch() {
    // org CA legitimately certified for orgA signs a member cert claiming orgB.
    let (ca, roots) = ca_and_roots();
    let (mut chain, _) = ca.member("orgA", "member-1", 20, 21);
    let member_key = SigningKey::from_bytes(&[21_u8; 32]);
    let org_key = SigningKey::from_bytes(&[20_u8; 32]);
    chain[0] = sign_cert_pub(
        Cert {
            org_namespace: "orgB".to_owned(),
            ..chain[0].clone()
        },
        &org_key,
    );
    let pop = SigningKey::from_bytes(&[22_u8; 32]);
    let token = enroll_token(
        &member_key,
        &pop,
        "orgB/prod",
        "peer-1",
        "agent",
        &["vm1"],
        FUTURE,
    );
    assert_eq!(
        verify_chain(&token, &chain, &roots, NOW),
        Err(ChainError::Chain)
    );
}

#[test]
fn rejects_wrong_length() {
    let (ca, roots) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgA/prod");
    let mut four = chain.clone();
    four.push(chain[0].clone());
    for c in [Vec::new(), chain[..1].to_vec(), chain[..2].to_vec(), four] {
        assert_eq!(
            verify_chain(&token, &c, &roots, NOW),
            Err(ChainError::Chain)
        );
    }
}

#[test]
fn rejects_wrong_role() {
    let (ca, roots) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgA/prod");
    let reordered = vec![chain[1].clone(), chain[0].clone(), chain[2].clone()];
    assert_eq!(
        verify_chain(&token, &reordered, &roots, NOW),
        Err(ChainError::Chain)
    );
}

#[test]
fn rejects_expired() {
    // Chain minted already-expired, and separately an expired enrollment.
    let expired_ca = DevCa::new(NOW - 1);
    let mut roots = RootMap::new();
    roots.add(expired_ca.root_id.clone(), expired_ca.root_pub);
    let (chain, member) = expired_ca.member("orgA", "member-1", 30, 31);
    let pop = SigningKey::from_bytes(&[32_u8; 32]);
    let token = enroll_token(
        &member,
        &pop,
        "orgA/prod",
        "peer-1",
        "agent",
        &["vm1"],
        FUTURE,
    );
    assert_eq!(
        verify_chain(&token, &chain, &roots, NOW),
        Err(ChainError::Expired)
    );

    let (ca, roots2) = ca_and_roots();
    let (chain2, member2) = ca.member("orgA", "member-1", 33, 34);
    let pop2 = SigningKey::from_bytes(&[35_u8; 32]);
    let expired_token = enroll_token(
        &member2,
        &pop2,
        "orgA/prod",
        "peer-1",
        "agent",
        &["vm1"],
        NOW - 1,
    );
    assert_eq!(
        verify_chain(&expired_token, &chain2, &roots2, NOW),
        Err(ChainError::Expired)
    );
}

#[test]
fn rejects_bad_enrollment_signature() {
    // Enrollment signed by a NON-member key: the chain is valid but the member
    // did not vouch for this enrollment.
    let (ca, roots) = ca_and_roots();
    let (chain, _) = ca.member("orgA", "member-1", 40, 41);
    let wrong = SigningKey::from_bytes(&[42_u8; 32]);
    let pop = SigningKey::from_bytes(&[43_u8; 32]);
    let token = enroll_token(
        &wrong,
        &pop,
        "orgA/prod",
        "peer-1",
        "agent",
        &["vm1"],
        FUTURE,
    );
    assert_eq!(
        verify_chain(&token, &chain, &roots, NOW),
        Err(ChainError::Enroll)
    );
}
