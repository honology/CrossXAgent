use crossx_relay::RelayError;

#[test]
fn maps_all_protocol_v1_error_codes() {
    let cases = [
        ("unauthenticated", RelayError::Unauthenticated),
        ("unauthorized", RelayError::Unauthorized),
        ("target_offline", RelayError::TargetOffline),
        ("registration_conflict", RelayError::RegistrationConflict),
        ("protocol_version", RelayError::ProtocolVersion),
    ];

    for (code, expected) in cases {
        assert_eq!(RelayError::from_wire_code(code), expected);
    }
}

#[test]
fn preserves_unknown_protocol_error_codes() {
    assert_eq!(
        RelayError::from_wire_code("future_code"),
        RelayError::Protocol("future_code".to_owned())
    );
}
