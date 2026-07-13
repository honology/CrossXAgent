use std::{
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crossx_relay::enroll::{self, Claims, Token};
use crossx_relay::{Peer, PeerKind, RelayConfig};
use ed25519_dalek::{Signer as _, SigningKey};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires RELAY_E2E=1, Go, and the sibling crossx-relay repository"]
async fn real_go_relay_register_dial_and_echo() {
    if std::env::var("RELAY_E2E").as_deref() != Ok("1") {
        return;
    }

    let go_repo = go_relay_repo();
    let material = tempfile::tempdir().unwrap();
    let generated = Command::new("go")
        .current_dir(&go_repo)
        .args(["run", "./cmd/devmaterial", "-out"])
        .arg(material.path())
        .status()
        .unwrap();
    assert!(generated.success(), "Go devmaterial generation failed");

    let relay_binary = material.path().join(if cfg!(windows) {
        "crossx-relay.exe"
    } else {
        "crossx-relay"
    });
    let built = Command::new("go")
        .current_dir(&go_repo)
        .args(["build", "-o"])
        .arg(&relay_binary)
        .arg("./cmd/relay")
        .status()
        .unwrap();
    assert!(built.success(), "Go relay build failed");

    let relay_port = unused_port();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    let relay = Command::new(&relay_binary)
        .args(["-listen", &relay_addr, "-peers"])
        .arg(material.path().join("peers.json"))
        .arg("-cert")
        .arg(material.path().join("relay-cert.pem"))
        .arg("-key")
        .arg(material.path().join("relay-key.pem"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _relay = ChildGuard(relay);
    wait_until_listening(&relay_addr).await;

    let root_cert_pem = std::fs::read(material.path().join("relay-cert.pem")).unwrap();
    let mut agent = Peer::connect(
        &config(
            &relay_addr,
            &root_cert_pem,
            material.path().join("agent.ed25519"),
            "agent-e2e",
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
        assert_eq!(proxy.header.proto, "tcp");
        assert_eq!(proxy.header.port, echo_port);
        let mut local = TcpStream::connect(("127.0.0.1", proxy.header.port))
            .await
            .unwrap();
        tokio::io::copy_bidirectional(&mut proxy.stream, &mut local)
            .await
            .unwrap();
    });

    let desktop = Peer::connect(
        &config(
            &relay_addr,
            &root_cert_pem,
            material.path().join("desktop.ed25519"),
            "desktop-e2e",
        ),
        PeerKind::Desktop,
    )
    .await
    .unwrap();
    let mut pipe = desktop.dial("e2e-node", "tcp", echo_port).await.unwrap();
    let message = b"hello from crossx-relay-rs";
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

fn go_relay_repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .join("crossx-relay")
}

fn unused_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_until_listening(addr: &str) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("Go relay did not start listening at {addr}");
}

fn config(addr: &str, cert: &[u8], seed_path: PathBuf, principal: &str) -> RelayConfig {
    let seed = std::fs::read_to_string(seed_path).unwrap();
    RelayConfig {
        addr: addr.to_owned(),
        root_cert_pem: cert.to_vec(),
        key_seed: STANDARD.decode(seed.trim()).unwrap().try_into().unwrap(),
        principal: principal.to_owned(),
        enrollment: None,
    }
}

fn read_seed(path: PathBuf) -> [u8; 32] {
    let encoded = std::fs::read_to_string(path).unwrap();
    STANDARD.decode(encoded.trim()).unwrap().try_into().unwrap()
}

fn enrollment_config(addr: &str, cert: &[u8], seed: [u8; 32], token: Token) -> RelayConfig {
    RelayConfig {
        addr: addr.to_owned(),
        root_cert_pem: cert.to_vec(),
        key_seed: seed,
        principal: String::new(),
        enrollment: Some(token),
    }
}

/// Bidirectional enrollment conformance against the real Go relay running the
/// EnrollmentAuthenticator: the agent presents the GO-signed enrollment from
/// devmaterial (Go -> Rust), and the desktop presents a RUST-signed enrollment
/// the Go relay must verify (Rust -> Go), then bytes echo end to end.
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

    // Build authorities.json from the devmaterial authority seed.
    let authority_key =
        SigningKey::from_bytes(&read_seed(material.path().join("authority.ed25519")));
    let authority_pub_b64 = STANDARD.encode(authority_key.verifying_key().to_bytes());
    let authorities_path = material.path().join("authorities.json");
    std::fs::write(
        &authorities_path,
        format!(r#"{{"authorities":[{{"project":"proj-e2e","pub":"{authority_pub_b64}"}}]}}"#),
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
        .arg("-authorities")
        .arg(&authorities_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _relay = ChildGuard(relay);
    wait_until_listening(&relay_addr).await;

    let root_cert_pem = std::fs::read(material.path().join("relay-cert.pem")).unwrap();

    // Agent: present the Go-signed enrollment from devmaterial.
    let agent_token: Token = serde_json::from_str(
        &std::fs::read_to_string(material.path().join("enrollment.json")).unwrap(),
    )
    .unwrap();
    let agent_seed = read_seed(material.path().join("agent.ed25519"));
    let mut agent = Peer::connect(
        &enrollment_config(&relay_addr, &root_cert_pem, agent_seed, agent_token),
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

    // Desktop: Rust-sign a desktop enrollment with the authority key; the Go relay
    // must verify it. A fixed test seed keeps the run deterministic.
    let desktop_seed = [9_u8; 32];
    let desktop_pub = SigningKey::from_bytes(&desktop_seed)
        .verifying_key()
        .to_bytes()
        .to_vec();
    let desktop_claims = Claims {
        v: enroll::V1,
        project: "proj-e2e".to_owned(),
        peer: "desktop-e2e".to_owned(),
        kind: "desktop".to_owned(),
        pub_key: desktop_pub,
        scope: vec!["e2e-node".to_owned()],
        exp: 4_102_444_800,
    };
    let desktop_sig = authority_key
        .sign(&enroll::canonical(&desktop_claims))
        .to_bytes()
        .to_vec();
    let desktop_token = Token {
        claims: desktop_claims,
        sig: desktop_sig,
    };
    let desktop = Peer::connect(
        &enrollment_config(&relay_addr, &root_cert_pem, desktop_seed, desktop_token),
        PeerKind::Desktop,
    )
    .await
    .unwrap();
    let mut pipe = desktop.dial("e2e-node", "tcp", echo_port).await.unwrap();
    let message = b"hello via enrollment";
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
