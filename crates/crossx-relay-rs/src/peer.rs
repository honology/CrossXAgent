use std::{
    future::poll_fn,
    io::{self, Cursor},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ed25519_dalek::{Signer as _, SigningKey};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{mpsc, oneshot},
    task::AbortHandle,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
        SignatureScheme,
        client::{
            WebPkiServerVerifier,
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        },
        pki_types::{CertificateDer, ServerName, UnixTime},
        version::TLS13,
    },
};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _, TokioAsyncReadCompatExt as _};
use yamux::{Connection, Mode, Stream};

use crate::{
    RelayError,
    auth::{enrollment_transcript, relay_binding, transcript},
    enroll,
    frame::{read_frame, write_frame},
    protocol::{
        AuthInit, AuthProof, AuthResp, Challenge, Dial, DialResp, ProxyHeader, Register,
        RegisterResp, VERSION,
    },
};

type OpenResult = Result<Stream, RelayError>;
type OpenRequest = oneshot::Sender<OpenResult>;
type InboundResult = Result<Stream, String>;

#[derive(Debug)]
struct PinnedCertificateVerifier {
    pinned_leaf: CertificateDer<'static>,
    signature_verifier: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() != self.pinned_leaf.as_ref() {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.signature_verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.signature_verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

/// Connection material for one authenticated relay peer.
pub struct RelayConfig {
    /// Relay TCP authority, such as `relay.example.com:8443`.
    pub addr: String,
    /// PEM containing the relay leaf certificate used as the sole trust root.
    pub root_cert_pem: Vec<u8>,
    /// Raw Ed25519 private-key seed registered for this principal.
    pub key_seed: [u8; 32],
    /// Registered principal identifier sent without normalization (M0 path).
    pub principal: String,
    /// Signed enrollment token. When present, the peer authenticates via the M1
    /// enrollment path (presenting the token and binding the proof to the full
    /// enrollment); `principal` is then unused — the identity is the token's peer.
    pub enrollment: Option<enroll::Token>,
}

/// Role claimed during the authentication handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerKind {
    /// Long-lived agent that registers a target and accepts proxy streams.
    Agent,
    /// Desktop or collector that opens target dial streams.
    Desktop,
}

impl PeerKind {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Desktop => "desktop",
        }
    }
}

/// Authenticated yamux client session over pinned TLS.
pub struct Peer {
    kind: PeerKind,
    control: RelayPipe,
    outbound: mpsc::Sender<OpenRequest>,
    inbound: mpsc::UnboundedReceiver<InboundResult>,
    driver: AbortHandle,
}

impl Peer {
    /// Establishes pinned TLS, starts yamux in client mode, and authenticates.
    pub async fn connect(cfg: &RelayConfig, kind: PeerKind) -> Result<Self, RelayError> {
        let (tls, binding) = connect_tls(cfg).await?;
        let connection = Connection::new(tls.compat(), yamux::Config::default(), Mode::Client);
        let (outbound, outbound_rx) = mpsc::channel(16);
        let (inbound_tx, inbound) = mpsc::unbounded_channel();
        let driver_task = tokio::spawn(drive_connection(connection, outbound_rx, inbound_tx));
        let driver = driver_task.abort_handle();

        let control_stream = match request_stream(&outbound).await {
            Ok(stream) => stream,
            Err(error) => {
                driver.abort();
                return Err(error);
            }
        };
        let mut control = RelayPipe::new(control_stream);
        if let Err(error) = authenticate(&mut control, cfg, kind, &binding).await {
            driver.abort();
            return Err(error);
        }

        Ok(Self {
            kind,
            control,
            outbound,
            inbound,
            driver,
        })
    }

    /// Registers an agent target and returns its opaque reconnect token.
    pub async fn register(&mut self, target_id: &str, proto: &str) -> Result<String, RelayError> {
        self.require_kind(PeerKind::Agent, "register")?;
        write_frame(
            &mut self.control,
            "register",
            &Register {
                target_id: target_id.to_owned(),
                proto: proto.to_owned(),
            },
        )
        .await?;
        let response: RegisterResp = read_frame(&mut self.control, "register_resp").await?;
        response_error(response.err)?;
        response.reconnect_token.ok_or_else(|| {
            RelayError::Protocol("successful register_resp omitted reconnect_token".to_owned())
        })
    }

    /// Accepts the next relay-initiated proxy stream and parses its header.
    pub async fn next_proxy(&mut self) -> Result<ProxyStream, RelayError> {
        self.require_kind(PeerKind::Agent, "next_proxy")?;
        let stream = self
            .inbound
            .recv()
            .await
            .ok_or_else(|| RelayError::Yamux("session driver stopped".to_owned()))?
            .map_err(RelayError::Yamux)?;
        let mut stream = RelayPipe::new(stream);
        let header = read_frame(&mut stream, "proxy_header").await?;
        Ok(ProxyStream { header, stream })
    }

    /// Opens a desktop stream, requests a target, and returns its raw data pipe.
    pub async fn dial(
        &self,
        target_id: &str,
        proto: &str,
        port: u16,
    ) -> Result<RelayPipe, RelayError> {
        self.require_kind(PeerKind::Desktop, "dial")?;
        let mut stream = RelayPipe::new(request_stream(&self.outbound).await?);
        write_frame(
            &mut stream,
            "dial",
            &Dial {
                target_id: target_id.to_owned(),
                proto: proto.to_owned(),
                port,
            },
        )
        .await?;
        let response: DialResp = read_frame(&mut stream, "dial_resp").await?;
        response_error(response.err)?;
        Ok(stream)
    }

    fn require_kind(&self, expected: PeerKind, operation: &str) -> Result<(), RelayError> {
        if self.kind != expected {
            return Err(RelayError::Protocol(format!(
                "{operation} is invalid for a {} peer",
                self.kind.wire_name()
            )));
        }
        Ok(())
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // The driver owns the TLS socket, so aborting it closes the whole session.
        self.driver.abort();
    }
}

/// Relay metadata paired with its now-unframed proxy data stream.
pub struct ProxyStream {
    /// Header sent by the relay before any tunneled bytes.
    pub header: ProxyHeader,
    /// Bidirectional tunnel stream positioned after the header frame.
    pub stream: RelayPipe,
}

/// Tokio I/O adapter over one yamux stream.
pub struct RelayPipe {
    inner: Compat<Stream>,
}

impl RelayPipe {
    fn new(stream: Stream) -> Self {
        Self {
            inner: stream.compat(),
        }
    }
}

impl AsyncRead for RelayPipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for RelayPipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn connect_tls(
    cfg: &RelayConfig,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, [u8; 32]), RelayError> {
    let mut roots = RootCertStore::empty();
    let mut pem = Cursor::new(&cfg.root_cert_pem);
    let certificates = rustls_pemfile::certs(&mut pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| RelayError::Tls(format!("invalid certificate PEM: {error}")))?;
    if certificates.is_empty() {
        return Err(RelayError::Tls(
            "certificate PEM contains no certificates".to_owned(),
        ));
    }
    let pinned_leaf = certificates[0].clone();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| RelayError::Tls(format!("invalid trust certificate: {error}")))?;
    }

    let signature_verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| RelayError::Tls(format!("invalid trust store: {error}")))?;
    let verifier = PinnedCertificateVerifier {
        pinned_leaf,
        signature_verifier,
    };
    let tls_config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = server_name(&cfg.addr)?;
    let socket = TcpStream::connect(&cfg.addr).await?;
    let tls = connector
        .connect(server_name, socket)
        .await
        .map_err(|error| RelayError::Tls(error.to_string()))?;
    let leaf_der = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(|| RelayError::Tls("relay supplied no leaf certificate".to_owned()))?;
    let binding = relay_binding(leaf_der.as_ref());
    Ok((tls, binding))
}

fn server_name(addr: &str) -> Result<ServerName<'static>, RelayError> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return Ok(ServerName::IpAddress(socket_addr.ip().into()));
    }
    let (host, _) = addr
        .rsplit_once(':')
        .ok_or_else(|| RelayError::Tls(format!("relay address has no port: {addr}")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(host.to_owned())
        .map_err(|error| RelayError::Tls(format!("invalid relay server name: {error}")))
}

async fn authenticate(
    control: &mut RelayPipe,
    cfg: &RelayConfig,
    kind: PeerKind,
    binding: &[u8; 32],
) -> Result<(), RelayError> {
    // With an enrollment present, authenticate via the M1 enrollment path: present
    // the signed token and bind the proof to the FULL enrollment. Otherwise use the
    // M0 bare-identity path. The relay picks the authenticator; the client just
    // signs the matching transcript.
    let principal_hint = match &cfg.enrollment {
        Some(token) => token.claims.peer.clone(),
        None => cfg.principal.clone(),
    };
    write_frame(
        control,
        "auth_init",
        &AuthInit {
            versions: vec![VERSION],
            kind: kind.wire_name().to_owned(),
            principal_hint,
            enrollment: cfg.enrollment.clone(),
        },
    )
    .await?;
    let challenge: Challenge = read_frame(control, "challenge").await?;
    if challenge.nonce.len() != 32 {
        return Err(RelayError::Protocol(format!(
            "challenge nonce has length {}, expected 32",
            challenge.nonce.len()
        )));
    }
    let signing_key = SigningKey::from_bytes(&cfg.key_seed);
    let proof_input = match &cfg.enrollment {
        Some(token) => {
            enrollment_transcript(binding, &enroll::canonical(&token.claims), &challenge.nonce)
        }
        None => transcript(binding, &cfg.principal, &challenge.nonce),
    };
    let proof = signing_key.sign(&proof_input);
    write_frame(
        control,
        "auth_proof",
        &AuthProof {
            signature: proof.to_bytes().to_vec(),
        },
    )
    .await?;
    let response: AuthResp = read_frame(control, "auth_resp").await?;
    response_error(response.err)?;
    if response.version != Some(VERSION) || response.session_id.is_none() {
        return Err(RelayError::Protocol(
            "successful auth_resp omitted session_id or protocol version 1".to_owned(),
        ));
    }
    Ok(())
}

fn response_error(error: Option<String>) -> Result<(), RelayError> {
    match error.as_deref() {
        None | Some("") => Ok(()),
        Some(code) => Err(RelayError::from_wire_code(code)),
    }
}

async fn request_stream(outbound: &mpsc::Sender<OpenRequest>) -> OpenResult {
    let (result_tx, result_rx) = oneshot::channel();
    outbound
        .send(result_tx)
        .await
        .map_err(|_| RelayError::Yamux("session driver stopped".to_owned()))?;
    result_rx
        .await
        .map_err(|_| RelayError::Yamux("session driver stopped".to_owned()))?
}

async fn drive_connection<T>(
    mut connection: Connection<T>,
    mut outbound: mpsc::Receiver<OpenRequest>,
    inbound: mpsc::UnboundedSender<InboundResult>,
) where
    T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            request = outbound.recv() => {
                let Some(request) = request else {
                    return;
                };
                let result = poll_fn(|cx| connection.poll_new_outbound(cx))
                    .await
                    .map_err(|error| RelayError::Yamux(error.to_string()));
                let _ = request.send(result);
            }
            stream = poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                match stream {
                    Some(Ok(stream)) => {
                        if inbound.send(Ok(stream)).is_err() {
                            return;
                        }
                    }
                    Some(Err(error)) => {
                        let message = error.to_string();
                        tracing::debug!(error = %message, "relay yamux driver stopped");
                        let _ = inbound.send(Err(message));
                        return;
                    }
                    None => {
                        let _ = inbound.send(Err("session closed".to_owned()));
                        return;
                    }
                }
            }
        }
    }
}
