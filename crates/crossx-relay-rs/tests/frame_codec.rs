use base64::{Engine as _, engine::general_purpose::STANDARD};
use crossx_relay::frame::{MAX_FRAME_SIZE, read_frame, write_frame};
use crossx_relay::protocol::{
    AuthInit, AuthProof, AuthResp, Challenge, Dial, DialResp, ProxyHeader, Register, RegisterResp,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

fn assert_payload<T>(payload: &T, expected: serde_json::Value)
where
    T: Serialize,
{
    assert_eq!(serde_json::to_value(payload).unwrap(), expected);
}

fn assert_decodes<T>(value: serde_json::Value)
where
    T: DeserializeOwned,
{
    serde_json::from_value::<T>(value).unwrap();
}

#[test]
fn protocol_v1_payloads_match_section_3_wire_json() {
    let nonce = STANDARD
        .decode("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
        .unwrap();
    let signature = vec![7_u8; 64];

    assert_payload(
        &AuthInit {
            versions: vec![1],
            kind: "agent".to_owned(),
            principal_hint: "principal-1".to_owned(),
            enrollment: None,
            chain: Vec::new(),
        },
        json!({"versions":[1],"kind":"agent","principal_hint":"principal-1"}),
    );
    assert_payload(
        &Challenge {
            nonce: nonce.clone(),
        },
        json!({"nonce": STANDARD.encode(&nonce)}),
    );
    assert_payload(
        &AuthProof {
            signature: signature.clone(),
        },
        json!({"signature": STANDARD.encode(&signature)}),
    );
    assert_payload(
        &AuthResp {
            session_id: Some("session-1".to_owned()),
            version: Some(1),
            err: None,
        },
        json!({"session_id":"session-1","version":1}),
    );
    assert_payload(
        &Register {
            target_id: "target-1".to_owned(),
            proto: "tcp".to_owned(),
        },
        json!({"target_id":"target-1","proto":"tcp"}),
    );
    assert_payload(
        &RegisterResp {
            reconnect_token: Some("token-1".to_owned()),
            err: None,
        },
        json!({"reconnect_token":"token-1"}),
    );
    assert_payload(
        &Dial {
            target_id: "target-1".to_owned(),
            proto: "tcp".to_owned(),
            port: 22,
        },
        json!({"target_id":"target-1","proto":"tcp","port":22}),
    );
    assert_payload(&DialResp { err: None }, json!({}));
    assert_payload(
        &ProxyHeader {
            tunnel_id: "tunnel-1".to_owned(),
            proto: "tcp".to_owned(),
            port: 22,
            client_addr: Some("127.0.0.1:1234".to_owned()),
        },
        json!({"tunnel_id":"tunnel-1","proto":"tcp","port":22,"client_addr":"127.0.0.1:1234"}),
    );

    assert_decodes::<AuthInit>(
        json!({"versions":[],"kind":"desktop","principal_hint":"p","unknown":true}),
    );
}

#[tokio::test]
async fn frame_codec_round_trips_without_consuming_following_bytes() {
    let (mut writer, mut reader) = tokio::io::duplex(256);
    let payload = Dial {
        target_id: "target-1".to_owned(),
        proto: "tcp".to_owned(),
        port: 22,
    };

    let write = tokio::spawn(async move {
        write_frame(&mut writer, "dial", &payload).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut writer, b"raw")
            .await
            .unwrap();
    });
    let decoded: Dial = read_frame(&mut reader, "dial").await.unwrap();
    assert_eq!(decoded.target_id, "target-1");
    let mut raw = [0_u8; 3];
    tokio::io::AsyncReadExt::read_exact(&mut reader, &mut raw)
        .await
        .unwrap();
    assert_eq!(&raw, b"raw");
    write.await.unwrap();
}

#[tokio::test]
async fn rejects_frames_larger_than_one_mibibyte() {
    let (mut writer, mut reader) = tokio::io::duplex(8);
    tokio::spawn(async move {
        tokio::io::AsyncWriteExt::write_all(
            &mut writer,
            &((MAX_FRAME_SIZE as u32) + 1).to_be_bytes(),
        )
        .await
        .unwrap();
    });

    let error = read_frame::<_, Dial>(&mut reader, "dial")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("frame length"));
}
