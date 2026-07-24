# crossx-relay-rs Chain Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the Rust `crossx-relay-rs` crate to build, present, and verify the `[member, org, issuing]` certificate chain-to-root that the Go relay now requires, byte-for-byte conformant with the Go `enroll` package, and prove it end-to-end against the real Go relay running `-roots`.

**Architecture:** The Go relay (merged `06c3751`) replaced the per-project authority model with chain-to-root: a peer presents a signed enrollment PLUS a `[member, org, issuing]` cert chain in `AUTH_INIT.chain`; the relay validates the chain to a trusted root offline (`enroll.VerifyChain`) and enforces `project ∈ org namespace`. This plan mirrors that in Rust: a normative `cert` module (`Cert`, `canonical_cert`, `verify_chain`) reproducing Go's `enroll/cert.go` + `enroll/chain.go` byte-for-byte, the wire field on `AuthInit`, the chain on `RelayConfig`, and conformance + live-E2E tests. The Rust side is BOTH a chain builder (agents present chains) and a chain verifier (for conformance); the Go relay stays authoritative for live authentication.

**Tech Stack:** Rust (crate `crossx-relay-rs`, edition/toolchain as pinned in the workspace), `ed25519-dalek` 2, `serde`/`serde_json`, `base64`, `thiserror`, `tokio`, `yamux`, `tokio-rustls`; the sibling Go `crossx-relay` repo for `cmd/devmaterial` golden material and the live relay binary.

## Global Constraints

- **`cert::canonical_cert` and `enroll::canonical` are the NORMATIVE cross-language interop surface — they MUST stay byte-identical to Go `enroll.CanonicalCert` / `enroll.Canonical`.** Domain tags: cert = `crossx-relay/cert/v1`, enroll = `crossx-relay/enroll/v1`. Encoding = `append_chunk` (u32-BE length prefix ∥ bytes), matching the existing `enroll::append_chunk`.
- **Go cert field order (from `enroll/cert.go` `CanonicalCert`):** tag, `subject_pub`, `subject_id`, `role`, `org_namespace`, `exp` (8-byte big-endian of `uint64(exp)`), `issuer_id`. `sig` is NOT in the canonical bytes.
- **Go `VerifyChain` semantics (from `enroll/chain.go`) to reproduce exactly:** chain length == 3; roles `[member, org, issuing]` positionally; every cert `exp` and the enrollment `exp` checked `exp <= 0 || now >= exp`; signatures `member ← org.subject_pub`, `org ← issuing.subject_pub`, `issuing ← roots.root(issuing.issuer_id)`; `member.org_namespace` non-empty and `== org.org_namespace`; enrollment verified against `member.subject_pub`; `within(project, member.org_namespace)` where `within` requires both be clean paths (no empty, `.`, or `..` segments) and `project == ns || project.starts_with(ns + "/")`.
- **`verify_strict` (dalek) is intentionally stricter than Go's `ed25519.Verify` (rejects non-canonical / small-order keys). This is defence-in-depth and NON-NORMATIVE:** honestly-signed material verifies identically on both sides. Keep using `verify_strict` for cert and enrollment signatures, consistent with the existing `enroll::verify`.
- **`#[serde(deny_unknown_fields)]` on `Cert`** (matches the Go relay's strict `DisallowUnknownFields` decoder and the existing `Claims`/`Token`).
- **`#![forbid(unsafe_code)]`** stays (crate-level, already in `lib.rs`).
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_013CjVump9HjLRJrGqNhyzpP
  ```
- **Gate before every commit** (run from `crates/crossx-relay-rs/`): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test -p crossx-relay` (unit + integration, excluding the `#[ignore]` live tests). The live E2E gate (Task 4) additionally runs `RELAY_E2E=1 cargo test -p crossx-relay -- --ignored` and requires Go + the sibling `crossx-relay` repo.

## File Structure

- `crates/crossx-relay-rs/src/cert.rs` (create) — `Cert`, role constants, `canonical_cert`, `verify_cert_sig`, `RootStore` trait, `RootMap`, `ChainError`, `verify_chain`, `within`, `clean_path`. Normative; stdlib + dalek + serde + base64 only, mirroring `enroll.rs`.
- `crates/crossx-relay-rs/src/lib.rs` (modify) — `pub mod cert;` + re-exports.
- `crates/crossx-relay-rs/src/protocol.rs` (modify) — `AuthInit.chain: Vec<Cert>`.
- `crates/crossx-relay-rs/src/peer.rs` (modify) — `RelayConfig.chain`, present it in `authenticate`, fix `base_cfg` test helper.
- `crates/crossx-relay-rs/tests/common/mod.rs` (create) — `DevCa` test helper (mint chains under a root) + `enroll_token`, shared by the integration tests.
- `crates/crossx-relay-rs/tests/chain_verify.rs` (create) — `verify_chain` reject/accept suite mirroring the Go `enroll/chain_test.go` mutation-killers.
- `crates/crossx-relay-rs/tests/cert_golden.rs` (create) — offline conformance: `verify_chain` accepts the Go `devmaterial` golden `chain.json`/`roots.json`.
- `crates/crossx-relay-rs/tests/enroll_golden.rs` (modify) — repoint from the removed `authority.seed` to the new member-signed golden material.
- `crates/crossx-relay-rs/tests/relay_e2e.rs` (modify) — replace the stale `-authorities` enrollment E2E with a `-roots` + chain E2E (Rust-minted chains, both directions).
- `crates/crossx-relay-rs/tests/fixtures/` (modify) — add `cert_golden_chain.json`, `cert_golden_roots.json`, `enroll_golden_member.seed`; refresh `enroll_golden_enrollment.json` + `enroll_golden_canonical.b64`; remove `enroll_golden_authority.seed`.

---

### Task 1: `cert::Cert` + `canonical_cert` + `verify_cert_sig`

**Files:**
- Create: `crates/crossx-relay-rs/src/cert.rs`
- Modify: `crates/crossx-relay-rs/src/lib.rs`

**Interfaces:**
- Consumes: `enroll::append_chunk`-style encoding (reimplemented privately here, matching `src/enroll.rs`).
- Produces: `pub struct Cert { subject_pub: Vec<u8>, subject_id: String, role: String, org_namespace: String, exp: i64, issuer_id: String, sig: Vec<u8> }`; `pub const ROLE_ISSUING/ROLE_ORG/ROLE_MEMBER: &str`; `pub fn canonical_cert(&Cert) -> Vec<u8>`; `pub fn verify_cert_sig(&Cert, issuer_pub: &[u8]) -> bool`.

- [ ] **Step 1: Write the failing round-trip test**

Add to the bottom of the new `src/cert.rs` (the module body is written in Step 3; write this test first and let it fail to compile):

```rust
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
        let other = SigningKey::from_bytes(&[3_u8; 32]).verifying_key().to_bytes();
        assert!(!verify_cert_sig(&cert, &other));

        // Malformed issuer key / signature length reject without panic.
        assert!(!verify_cert_sig(&cert, &[0_u8; 31]));
        let mut bad_sig = cert.clone();
        bad_sig.sig.truncate(63);
        assert!(!verify_cert_sig(&bad_sig, &issuer_pub));
    }
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `cargo test -p crossx-relay --lib cert 2>&1 | head -20`
Expected: FAIL — `cannot find type Cert` / `canonical_cert` unresolved (module body not yet written).

- [ ] **Step 3: Write the module body**

Put this ABOVE the `#[cfg(test)]` block in `src/cert.rs`:

```rust
//! The crossx-relay certificate chain-to-root. A peer presents a
//! `[member, org, issuing]` chain that the relay validates offline up to a
//! trusted root. `canonical_cert` is the NORMATIVE cross-language interop
//! surface — it reproduces the Go `enroll.CanonicalCert` (crossx-relay repo,
//! `enroll/cert.go`) byte-for-byte, and the `cert_golden` conformance test pins
//! that against Go `devmaterial` output.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

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
```

Then register the module in `src/lib.rs` — after `pub mod auth;` add `pub mod cert;`, and extend the re-export line:

```rust
pub use cert::{Cert, ChainError, RootMap, RootStore, verify_chain};
```

(Note: `ChainError`, `RootMap`, `RootStore`, `verify_chain` are added in Task 2; add them to this `pub use` now and they resolve after Task 2. If you split commits, add only `Cert` here in Task 1 and extend in Task 2.)

- [ ] **Step 4: Run the test to confirm it passes**

Run: `cargo test -p crossx-relay --lib cert`
Expected: PASS (`verify_cert_sig_accepts_honest_signature_and_rejects_tampering`).

- [ ] **Step 5: Commit**

```bash
git add crates/crossx-relay-rs/src/cert.rs crates/crossx-relay-rs/src/lib.rs
git commit -m "feat(cert): compact Cert type + canonical_cert + verify_cert_sig"
```

---

### Task 2: `verify_chain` + `RootStore`/`RootMap` + reject suite

**Files:**
- Modify: `crates/crossx-relay-rs/src/cert.rs`
- Modify: `crates/crossx-relay-rs/src/lib.rs` (re-exports, if not already added in Task 1)
- Create: `crates/crossx-relay-rs/tests/common/mod.rs`
- Create: `crates/crossx-relay-rs/tests/chain_verify.rs`

**Interfaces:**
- Consumes: `Cert`, `canonical_cert`, `verify_cert_sig` (Task 1); `enroll::{Token, Claims, canonical, verify, V1}`.
- Produces: `pub trait RootStore { fn root(&self, id: &str) -> Option<[u8; 32]>; }`; `pub struct RootMap` (`new`, `add`, `RootStore`); `pub enum ChainError { Chain, UntrustedRoot, Expired, CrossOrg, Enroll }`; `pub fn verify_chain(&Token, &[Cert], &impl RootStore, now_unix: i64) -> Result<Claims, ChainError>`. Test helper `common::DevCa { new(exp), root_id, root_pub, member(ns, member_id, org_seed, member_seed) -> (Vec<Cert>, SigningKey), issuing_cert }` + `common::enroll_token(member: &SigningKey, peer_pop: &SigningKey, project, peer, kind, scope, exp) -> Token`.

- [ ] **Step 1: Write the failing chain-verify suite**

Create `crates/crossx-relay-rs/tests/common/mod.rs`:

```rust
//! Test-only chain minting (mirrors the Go `devcerts.DevCA`). It mints trust —
//! integration-test use only.

use crossx_relay::cert::{Cert, ROLE_ISSUING, ROLE_MEMBER, ROLE_ORG, canonical_cert};
use crossx_relay::enroll::{self, Claims, Token};
use ed25519_dalek::{Signer as _, SigningKey};

fn sign_cert(mut cert: Cert, issuer: &SigningKey) -> Cert {
    cert.sig = issuer.sign(&canonical_cert(&cert)).to_bytes().to_vec();
    cert
}

/// A test CA: one root + one issuing CA, minting per-org member chains that all
/// trace to the same root.
pub struct DevCa {
    pub root_id: String,
    pub root_pub: [u8; 32],
    issuing: SigningKey,
    pub issuing_cert: Cert,
    exp: i64,
}

impl DevCa {
    #[must_use]
    pub fn new(exp: i64) -> Self {
        let root = SigningKey::from_bytes(&[10_u8; 32]);
        let issuing = SigningKey::from_bytes(&[11_u8; 32]);
        let issuing_cert = sign_cert(
            Cert {
                subject_pub: issuing.verifying_key().to_bytes().to_vec(),
                subject_id: "issuing".to_owned(),
                role: ROLE_ISSUING.to_owned(),
                org_namespace: String::new(),
                exp,
                issuer_id: "rust-dev-root".to_owned(),
                sig: Vec::new(),
            },
            &root,
        );
        Self {
            root_id: "rust-dev-root".to_owned(),
            root_pub: root.verifying_key().to_bytes(),
            issuing,
            issuing_cert,
            exp,
        }
    }

    /// Mints an org CA for `ns` (from `org_seed`) and a member cert under it
    /// (from `member_seed`), returning the `[member, org, issuing]` chain and the
    /// member's cert signing key (which signs enrollments).
    #[must_use]
    pub fn member(
        &self,
        ns: &str,
        member_id: &str,
        org_seed: u8,
        member_seed: u8,
    ) -> (Vec<Cert>, SigningKey) {
        let org = SigningKey::from_bytes(&[org_seed; 32]);
        let member = SigningKey::from_bytes(&[member_seed; 32]);
        let org_cert = sign_cert(
            Cert {
                subject_pub: org.verifying_key().to_bytes().to_vec(),
                subject_id: ns.to_owned(),
                role: ROLE_ORG.to_owned(),
                org_namespace: ns.to_owned(),
                exp: self.exp,
                issuer_id: "issuing".to_owned(),
                sig: Vec::new(),
            },
            &self.issuing,
        );
        let member_cert = sign_cert(
            Cert {
                subject_pub: member.verifying_key().to_bytes().to_vec(),
                subject_id: member_id.to_owned(),
                role: ROLE_MEMBER.to_owned(),
                org_namespace: ns.to_owned(),
                exp: self.exp,
                issuer_id: ns.to_owned(),
                sig: Vec::new(),
            },
            &org,
        );
        (vec![member_cert, org_cert, self.issuing_cert.clone()], member)
    }
}

/// Signs an enrollment whose PoP key is `peer_pop`'s public key, with the member
/// cert key `member` (the chain's leaf signing key). Mirrors the Go split: the
/// member key signs the enrollment; `claims.pub` is the peer's separate PoP key.
#[must_use]
pub fn enroll_token(
    member: &SigningKey,
    peer_pop: &SigningKey,
    project: &str,
    peer: &str,
    kind: &str,
    scope: &[&str],
    exp: i64,
) -> Token {
    let claims = Claims {
        v: enroll::V1,
        project: project.to_owned(),
        peer: peer.to_owned(),
        kind: kind.to_owned(),
        pub_key: peer_pop.verifying_key().to_bytes().to_vec(),
        scope: scope.iter().map(|s| (*s).to_owned()).collect(),
        exp,
    };
    let sig = member.sign(&enroll::canonical(&claims)).to_bytes().to_vec();
    Token { claims, sig }
}
```

Create `crates/crossx-relay-rs/tests/chain_verify.rs` (mirrors Go `enroll/chain_test.go`):

```rust
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
    assert_eq!(verify_chain(&token, &chain, &roots, NOW), Err(ChainError::CrossOrg));
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
    assert_eq!(verify_chain(&token, &chain, &roots, NOW), Err(ChainError::UntrustedRoot));
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
        Cert { org_namespace: "orgB".to_owned(), ..chain[0].clone() },
        &org_key,
    );
    let pop = SigningKey::from_bytes(&[22_u8; 32]);
    let token = enroll_token(&member_key, &pop, "orgB/prod", "peer-1", "agent", &["vm1"], FUTURE);
    assert_eq!(verify_chain(&token, &chain, &roots, NOW), Err(ChainError::Chain));
}

#[test]
fn rejects_wrong_length() {
    let (ca, roots) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgA/prod");
    let mut four = chain.clone();
    four.push(chain[0].clone());
    for c in [Vec::new(), chain[..1].to_vec(), chain[..2].to_vec(), four] {
        assert_eq!(verify_chain(&token, &c, &roots, NOW), Err(ChainError::Chain));
    }
}

#[test]
fn rejects_wrong_role() {
    let (ca, roots) = ca_and_roots();
    let (chain, token) = valid(&ca, "orgA/prod");
    let reordered = vec![chain[1].clone(), chain[0].clone(), chain[2].clone()];
    assert_eq!(verify_chain(&token, &reordered, &roots, NOW), Err(ChainError::Chain));
}

#[test]
fn rejects_expired() {
    // Chain minted already-expired, and separately an expired enrollment.
    let expired_ca = DevCa::new(NOW - 1);
    let mut roots = RootMap::new();
    roots.add(expired_ca.root_id.clone(), expired_ca.root_pub);
    let (chain, member) = expired_ca.member("orgA", "member-1", 30, 31);
    let pop = SigningKey::from_bytes(&[32_u8; 32]);
    let token = enroll_token(&member, &pop, "orgA/prod", "peer-1", "agent", &["vm1"], FUTURE);
    assert_eq!(verify_chain(&token, &chain, &roots, NOW), Err(ChainError::Expired));

    let (ca, roots2) = ca_and_roots();
    let (chain2, member2) = ca.member("orgA", "member-1", 33, 34);
    let pop2 = SigningKey::from_bytes(&[35_u8; 32]);
    let expired_token = enroll_token(&member2, &pop2, "orgA/prod", "peer-1", "agent", &["vm1"], NOW - 1);
    assert_eq!(verify_chain(&expired_token, &chain2, &roots2, NOW), Err(ChainError::Expired));
}

#[test]
fn rejects_bad_enrollment_signature() {
    // Enrollment signed by a NON-member key: the chain is valid but the member
    // did not vouch for this enrollment.
    let (ca, roots) = ca_and_roots();
    let (chain, _) = ca.member("orgA", "member-1", 40, 41);
    let wrong = SigningKey::from_bytes(&[42_u8; 32]);
    let pop = SigningKey::from_bytes(&[43_u8; 32]);
    let token = enroll_token(&wrong, &pop, "orgA/prod", "peer-1", "agent", &["vm1"], FUTURE);
    assert_eq!(verify_chain(&token, &chain, &roots, NOW), Err(ChainError::Enroll));
}
```

Add a small re-signing helper to `tests/common/mod.rs` used above (keeps the tests terse):

```rust
/// Re-signs `cert` with `issuer` (recomputing the canonical over its current
/// fields). Used by tests to forge or mutate a link.
#[must_use]
pub fn sign_cert_pub(cert: Cert, issuer: &SigningKey) -> Cert {
    sign_cert(cert, issuer)
}
```

- [ ] **Step 2: Run to confirm it fails**

Run: `cargo test -p crossx-relay --test chain_verify 2>&1 | head -20`
Expected: FAIL — `verify_chain`, `RootMap`, `ChainError` unresolved.

- [ ] **Step 3: Implement `RootStore`, `RootMap`, `ChainError`, `verify_chain`, `within`, `clean_path`**

Add to `src/cert.rs` (above the `#[cfg(test)]` block), and ensure the `use` line imports what's needed:

```rust
use std::collections::HashMap;

use crate::enroll::{self, Claims, Token};

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
    let root_pub = roots.root(&issuing.issuer_id).ok_or(ChainError::UntrustedRoot)?;
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
    !s.is_empty() && s.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}
```

Confirm `src/lib.rs` re-exports include `ChainError, RootMap, RootStore, verify_chain` (added in Task 1 Step 3).

- [ ] **Step 4: Run to confirm the suite passes**

Run: `cargo test -p crossx-relay --test chain_verify`
Expected: PASS — all reject/accept cases green.

- [ ] **Step 5: Commit**

```bash
git add crates/crossx-relay-rs/src/cert.rs crates/crossx-relay-rs/src/lib.rs \
        crates/crossx-relay-rs/tests/common/mod.rs crates/crossx-relay-rs/tests/chain_verify.rs
git commit -m "feat(cert): verify_chain (member->org->issuing->root) + project-in-org + reject suite"
```

---

### Task 3: Golden fixtures + offline conformance vs Go `devmaterial`

**Files:**
- Create (regenerated): `crates/crossx-relay-rs/tests/fixtures/cert_golden_chain.json`, `cert_golden_roots.json`, `enroll_golden_member.seed`
- Modify (refresh): `crates/crossx-relay-rs/tests/fixtures/enroll_golden_enrollment.json`, `enroll_golden_canonical.b64`
- Delete: `crates/crossx-relay-rs/tests/fixtures/enroll_golden_authority.seed`
- Create: `crates/crossx-relay-rs/tests/cert_golden.rs`
- Modify: `crates/crossx-relay-rs/tests/enroll_golden.rs`

**Interfaces:**
- Consumes: Go `cmd/devmaterial` output (`chain.json`, `roots.json`, `member.ed25519`, `enrollment.json`, `enrollment-canonical.b64`); `verify_chain`, `RootMap` (Task 2); `enroll::verify`.
- Produces: committed golden fixtures + the `cert_golden` conformance test (Go golden chain accepted by Rust `verify_chain`), which — because `verify_cert_sig` recomputes `canonical_cert` and checks the Go signature — is ALSO the byte-conformance proof for `canonical_cert` (a one-byte divergence fails the signature).

- [ ] **Step 1: Regenerate the golden fixtures from Go `devmaterial`**

Run from the repo root (`CrossXCloud/`; adjust the scratch dir if needed):

```bash
DM="$(mktemp -d)"
( cd crossx-relay && go run ./cmd/devmaterial -out "$DM" )
FX=crossx-agent/crates/crossx-relay-rs/tests/fixtures
cp "$DM/chain.json"                 "$FX/cert_golden_chain.json"
cp "$DM/roots.json"                 "$FX/cert_golden_roots.json"
cp "$DM/member.ed25519"             "$FX/enroll_golden_member.seed"
cp "$DM/enrollment.json"            "$FX/enroll_golden_enrollment.json"
cp "$DM/enrollment-canonical.b64"   "$FX/enroll_golden_canonical.b64"
rm -f "$FX/enroll_golden_authority.seed"
```

Sanity: `chain.json` is a 3-element array of certs with far-future `exp` (2100 — the devmaterial expiry fix from relay `0b0208c`, so these fixtures do NOT rot); `roots.json` is `{"roots":[{"id":"dev-root","pub":"…"}]}`; `enrollment.json` is now MEMBER-signed (no separate authority).

- [ ] **Step 2: Write the failing conformance test**

Create `crates/crossx-relay-rs/tests/cert_golden.rs`:

```rust
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
```

- [ ] **Step 3: Repoint `enroll_golden.rs` to the member-signed material**

In `crates/crossx-relay-rs/tests/enroll_golden.rs`, replace the `authority_pub` helper (which read the now-deleted `enroll_golden_authority.seed`) with a member-key helper, and update the verify test:

```rust
fn member_pub() -> [u8; 32] {
    let seed_b64 = include_str!("fixtures/enroll_golden_member.seed").trim();
    let seed: [u8; 32] = STANDARD
        .decode(seed_b64)
        .expect("member seed is base64")
        .try_into()
        .expect("member seed is 32 bytes");
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}
```

Then in `verify_accepts_go_signed_enrollment` and `verify_rejects_tampered_claims`, replace `&authority_pub()` with `&member_pub()`. The `canonical_matches_go_golden_byte_for_byte` test is unchanged (the canonical format is unaffected by who signs). Leave `verify_rejects_wrong_authority` as-is but rename its intent — it already uses an unrelated `[7u8;32]` key, which is now simply "a non-member key"; rename the fn to `verify_rejects_wrong_signer` for accuracy.

- [ ] **Step 4: Run to confirm both suites pass**

Run: `cargo test -p crossx-relay --test cert_golden --test enroll_golden`
Expected: PASS — golden chain verifies; enroll conformance green against the member-signed fixtures.

- [ ] **Step 5: Commit**

```bash
git add crates/crossx-relay-rs/tests/fixtures crates/crossx-relay-rs/tests/cert_golden.rs \
        crates/crossx-relay-rs/tests/enroll_golden.rs
git commit -m "test(cert): golden chain conformance vs Go devmaterial; enroll golden -> member key"
```

---

### Task 4: Present the chain on the wire + live `-roots` E2E

**Files:**
- Modify: `crates/crossx-relay-rs/src/protocol.rs` (`AuthInit.chain`)
- Modify: `crates/crossx-relay-rs/src/peer.rs` (`RelayConfig.chain`, `authenticate`, `base_cfg`)
- Modify: `crates/crossx-relay-rs/tests/relay_e2e.rs` (`-roots` + chain E2E; update `config`/`enrollment_config`)

**Interfaces:**
- Consumes: `cert::Cert` (Task 1); `common::DevCa`, `common::enroll_token` (Task 2).
- Produces: `AuthInit.chain: Vec<Cert>` (JSON key `chain`, omitted when empty); `RelayConfig.chain: Vec<Cert>`; `authenticate` presents `cfg.chain` alongside `cfg.enrollment`.

- [ ] **Step 1: Add the wire field + config field (unit-level)**

In `src/protocol.rs`, add to `AuthInit` after `enrollment`:

```rust
    /// `[member, org, issuing]` chain authorizing the enrollment's signer up to a
    /// trusted root. Omitted (and not serialized) on the M0 pubkey path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<crate::cert::Cert>,
```

In `src/peer.rs`, add `use crate::cert::Cert;` to the imports, then add to `RelayConfig` after `enrollment`:

```rust
    /// Cert chain presented alongside `enrollment` on the M1 chain path. Empty on
    /// the M0 pubkey path.
    pub chain: Vec<Cert>,
```

Then in `authenticate`, extend the `AuthInit` literal:

```rust
        &AuthInit {
            versions: vec![VERSION],
            kind: kind.wire_name().to_owned(),
            principal_hint,
            enrollment: cfg.enrollment.clone(),
            chain: cfg.chain.clone(),
        },
```

Update the `base_cfg()` helper in `peer.rs`'s `#[cfg(test)] mod tests` to include `chain: Vec::new(),`. (The two `proof_transcript` unit tests are unaffected — the chain does not enter the PoP transcript.)

Two other `AuthInit` construction sites must gain `chain: Vec::new(),`:
- `tests/frame_codec.rs:31` (the `AuthInit { versions, kind, principal_hint, enrollment }` literal in `protocol_v1_payloads_match_section_3_wire_json`). Its expected JSON is unchanged: with an empty `chain` and `skip_serializing_if = "Vec::is_empty"`, the `chain` key is omitted, so `{"versions":[1],"kind":"agent","principal_hint":"principal-1"}` still matches.
- `src/peer.rs::authenticate` (handled above).

- [ ] **Step 2: Run the unit + non-ignored suites to confirm the crate still builds green**

Run: `cargo test -p crossx-relay`
Expected: PASS — `chain_verify`, `cert_golden`, `enroll_golden`, `frame_codec`, `error_codes`, `transcript_golden`, and the `peer` unit tests all green; the two `relay_e2e` tests are `#[ignore]` and skipped.

- [ ] **Step 3: Rewrite the enrollment E2E for `-roots` + chain**

In `crates/crossx-relay-rs/tests/relay_e2e.rs`: add `mod common;` at the top, and replace the whole `real_go_relay_enrollment_register_dial_and_echo` test. The old body built `authorities.json` and passed `-authorities` (both removed from the Go relay); the new body mints Rust chains under one root, writes `roots.json`, passes `-roots`, and presents chains for both peers. Also add `chain: Vec::new(),` to the existing `config` helper's `RelayConfig` and add a chain-aware config builder:

```rust
fn enrollment_chain_config(
    addr: &str,
    cert: &[u8],
    pop_seed: [u8; 32],
    token: crossx_relay::enroll::Token,
    chain: Vec<crossx_relay::cert::Cert>,
) -> RelayConfig {
    RelayConfig {
        addr: addr.to_owned(),
        root_cert_pem: cert.to_vec(),
        key_seed: pop_seed,
        principal: String::new(),
        enrollment: Some(token),
        chain,
    }
}
```

New test body:

```rust
#[tokio::test]
#[ignore = "requires RELAY_E2E=1, Go, and the sibling crossx-relay repository"]
async fn real_go_relay_enrollment_register_dial_and_echo() {
    if std::env::var("RELAY_E2E").as_deref() != Ok("1") {
        return;
    }

    let go_repo = go_relay_repo();
    let material = tempfile::tempdir().unwrap();
    assert!(
        Command::new("go")
            .current_dir(&go_repo)
            .args(["run", "./cmd/devmaterial", "-out"])
            .arg(material.path())
            .status()
            .unwrap()
            .success(),
        "Go devmaterial generation failed"
    );

    let relay_binary = material.path().join(if cfg!(windows) {
        "crossx-relay.exe"
    } else {
        "crossx-relay"
    });
    assert!(
        Command::new("go")
            .current_dir(&go_repo)
            .args(["build", "-o"])
            .arg(&relay_binary)
            .arg("./cmd/relay")
            .status()
            .unwrap()
            .success(),
        "Go relay build failed"
    );

    // Mint agent + desktop chains under one Rust dev-CA root, and trust that root.
    const FUTURE: i64 = 4_102_444_800;
    let ca = common::DevCa::new(FUTURE);
    let roots_path = material.path().join("roots.json");
    std::fs::write(
        &roots_path,
        format!(
            r#"{{"roots":[{{"id":"{}","pub":"{}"}}]}}"#,
            ca.root_id,
            STANDARD.encode(ca.root_pub)
        ),
    )
    .unwrap();

    let relay_port = unused_port();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    let relay = Command::new(&relay_binary)
        .args(["-listen", &relay_addr, "-peers"])
        .arg(material.path().join("peers.json"))
        .arg("-cert")
        .arg(material.path().join("relay-cert.pem"))
        .arg("-key")
        .arg(material.path().join("relay-key.pem"))
        .arg("-roots")
        .arg(&roots_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _relay = ChildGuard(relay);
    wait_until_listening(&relay_addr).await;

    let root_cert_pem = std::fs::read(material.path().join("relay-cert.pem")).unwrap();

    // Agent chain + PoP key.
    let (agent_chain, agent_member) = ca.member("proj-e2e", "agent-e2e", 50, 51);
    let agent_pop = SigningKey::from_bytes(&[52_u8; 32]);
    let agent_token = common::enroll_token(
        &agent_member, &agent_pop, "proj-e2e", "agent-e2e", "agent", &["e2e-node"], FUTURE,
    );
    let mut agent = Peer::connect(
        &enrollment_chain_config(
            &relay_addr, &root_cert_pem, [52_u8; 32], agent_token, agent_chain,
        ),
        PeerKind::Agent,
    )
    .await
    .unwrap();
    agent.register("e2e-node", "tcp").await.unwrap();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = echo_listener.accept().await.unwrap();
        let (mut reader, mut writer) = socket.split();
        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });
    let proxy_task = tokio::spawn(async move {
        let mut proxy = agent.next_proxy().await.unwrap();
        let mut local = TcpStream::connect(("127.0.0.1", proxy.header.port))
            .await
            .unwrap();
        tokio::io::copy_bidirectional(&mut proxy.stream, &mut local)
            .await
            .unwrap();
    });

    // Desktop chain + PoP key (same org, distinct keys, kind=desktop).
    let (desktop_chain, desktop_member) = ca.member("proj-e2e", "desktop-e2e", 60, 61);
    let desktop_pop = SigningKey::from_bytes(&[62_u8; 32]);
    let desktop_token = common::enroll_token(
        &desktop_member, &desktop_pop, "proj-e2e", "desktop-e2e", "desktop", &["e2e-node"], FUTURE,
    );
    let desktop = Peer::connect(
        &enrollment_chain_config(
            &relay_addr, &root_cert_pem, [62_u8; 32], desktop_token, desktop_chain,
        ),
        PeerKind::Desktop,
    )
    .await
    .unwrap();
    let mut pipe = desktop.dial("e2e-node", "tcp", echo_port).await.unwrap();
    let message = b"hello via chain enrollment";
    pipe.write_all(message).await.unwrap();
    let mut echoed = vec![0_u8; message.len()];
    pipe.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, message);
    drop(pipe);
    drop(desktop);

    tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), echo_task)
        .await
        .unwrap()
        .unwrap();
}
```

Delete the now-unused `enrollment_config` and `read_seed` helpers if nothing else references them (the M0 `real_go_relay_register_dial_and_echo` test still uses `config`, which keeps `read_seed`? No — `config` reads the seed inline. Remove `read_seed` and `enrollment_config` only if `cargo build` reports them unused; clippy `-D warnings` will flag dead code). Add `chain: Vec::new(),` to the `config` helper's `RelayConfig` literal so the M0 path still compiles.

- [ ] **Step 4: Run the live E2E**

Run: `RELAY_E2E=1 cargo test -p crossx-relay -- --ignored`
Expected: PASS — both `real_go_relay_register_dial_and_echo` (M0 pubkey path) and `real_go_relay_enrollment_register_dial_and_echo` (M1 chain path) drive register → dial → echo against the real Go relay, the second one presenting Rust-minted chains verified by Go `VerifyChain` under `-roots`.

- [ ] **Step 5: Full gate + commit**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test -p crossx-relay`
Expected: fmt clean; clippy 0 warnings; all non-ignored tests PASS.

```bash
git add crates/crossx-relay-rs/src/protocol.rs crates/crossx-relay-rs/src/peer.rs \
        crates/crossx-relay-rs/tests/relay_e2e.rs
git commit -m "feat(peer): present [member,org,issuing] chain in AUTH_INIT; -roots live E2E"
```

---

## On completion (do not skip)

- Update the crate/module docs if `crossx-relay-rs` has a README or `docs/` note describing the M1 enrollment path — it should mention the chain-to-root model and `RelayConfig.chain`, not the old per-project authority.
- The daemon (`crates/crossx-agent/src/relay.rs`) does not yet construct the crate's `crossx_relay::RelayConfig` for a live connection (VM relay wiring is the agent's later milestone). When it does — and when plan #4 injects the agent's chain via cloud-init — `RelayConfig.chain` must be populated from the injected chain material. No daemon change is required by THIS plan; note it for plan #4.
- Record completion in the [[crossx-relay-initiative]] memory: plan #2 done, crossx-relay-rs chain-conformant + live-E2E-green vs the `-roots` Go relay; next is plan #3 (hosted PKI backend).

## Self-Review Notes

- **Spec coverage:** cert type + canonical (T1) ✓; verify_chain + project-in-org + reject matrix (T2) ✓; golden conformance vs Go devmaterial (T3) ✓; wire presentation + live `-roots` E2E (T4) ✓. The stale `-authorities` E2E is explicitly replaced (T4).
- **Type consistency:** `Cert` field names/order match Go JSON tags and `CanonicalCert`; `ChainError` variants map to the Go sentinels (`ErrChain`/`ErrUntrustedRoot`/`ErrExpired`/`ErrCrossOrg`) plus `Enroll`; `verify_chain` signature and check order mirror Go `VerifyChain` line-for-line.
- **Normativity:** `canonical_cert` byte-conformance is proven transitively by `cert_golden` (Go signature over Go canonical must verify against Rust-recomputed canonical). `verify_strict` divergence from Go is documented as non-normative defence-in-depth.
