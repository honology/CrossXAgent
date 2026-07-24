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
        (
            vec![member_cert, org_cert, self.issuing_cert.clone()],
            member,
        )
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

/// Re-signs `cert` with `issuer` (recomputing the canonical over its current
/// fields). Used by tests to forge or mutate a link. Only `chain_verify.rs`
/// exercises the reject-suite paths that need this; `relay_e2e.rs` also builds
/// this `tests/common` module (each integration-test binary compiles its own
/// copy) but only mints well-formed chains, so this helper is legitimately
/// unused there.
#[must_use]
#[allow(dead_code)]
pub fn sign_cert_pub(cert: Cert, issuer: &SigningKey) -> Cert {
    sign_cert(cert, issuer)
}
