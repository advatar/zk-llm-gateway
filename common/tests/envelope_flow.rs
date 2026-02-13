use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use zk_llm_common::envelope::{
    open_request_at_gateway, seal_request_for_gateway, seal_response_at_gateway, Envelope,
    GatewayKeypair,
};
use zk_llm_common::token::TokenClass;

#[test]
fn request_and_response_roundtrip() {
    let gateway_keypair = GatewayKeypair::generate();
    let request_plaintext =
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#;

    let (request_env, client_ctx) = seal_request_for_gateway(
        gateway_keypair.public_bytes(),
        TokenClass::C512,
        request_plaintext,
    )
    .expect("request seal should succeed");

    let opened_request = open_request_at_gateway(&gateway_keypair, &request_env)
        .expect("gateway should decrypt request");
    assert_eq!(opened_request, request_plaintext);

    let response_plaintext = br#"{"kind":"ok","response":{"output":"world"}}"#;
    let response_env = seal_response_at_gateway(&gateway_keypair, &request_env, response_plaintext)
        .expect("response seal should succeed");

    let opened_response = client_ctx
        .open_response(&response_env)
        .expect("client should decrypt response");
    assert_eq!(opened_response, response_plaintext);
}

#[test]
fn tampered_request_ciphertext_is_rejected() {
    let gateway_keypair = GatewayKeypair::generate();
    let (mut env, _ctx) = seal_request_for_gateway(
        gateway_keypair.public_bytes(),
        TokenClass::C256,
        br#"{"prompt":"test"}"#,
    )
    .expect("request seal should succeed");

    let mut ciphertext = B64
        .decode(&env.ciphertext_b64)
        .expect("valid ciphertext b64");
    ciphertext[0] ^= 0x01;
    env.ciphertext_b64 = B64.encode(ciphertext);

    let err = open_request_at_gateway(&gateway_keypair, &env).expect_err("tampering must fail");
    assert!(err.to_string().contains("AEAD decrypt failed"));
}

#[test]
fn version_mismatch_is_rejected() {
    let gateway_keypair = GatewayKeypair::generate();
    let (request_env, client_ctx) = seal_request_for_gateway(
        gateway_keypair.public_bytes(),
        TokenClass::C256,
        br#"{"request":"v"}"#,
    )
    .expect("request seal should succeed");

    let mut bad_request = request_env.clone();
    bad_request.version = Envelope::VERSION + 1;
    assert!(open_request_at_gateway(&gateway_keypair, &bad_request).is_err());

    let good_response = seal_response_at_gateway(&gateway_keypair, &request_env, br#"{"ok":true}"#)
        .expect("response seal should succeed");
    let mut bad_response = good_response;
    bad_response.version = Envelope::VERSION + 1;
    assert!(client_ctx.open_response(&bad_response).is_err());
}
