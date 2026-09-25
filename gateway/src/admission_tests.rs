//! Synthetic HTTP tests over the actual production router and handlers.
//! These tests do NOT establish payment finality, hardware or clinical qualification.
use super::*;
use std::sync::{atomic::{AtomicUsize, Ordering}, Mutex};
use zk_llm_common::{
    envelope::{seal_request_for_gateway, ClientCryptoContext, Envelope},
    token::TokenClass,
    zk::{B64Bytes, VerifiedTicket, ZkTicket},
};

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) { self.task.abort(); }
}

async fn serve(app: Router) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    Server { url, task }
}

struct Probe {
    calls: AtomicUsize,
    body: Mutex<Option<Value>>,
    mode: u8,
    redirect: Option<String>,
}

async fn upstream(State(probe): State<Arc<Probe>>, body: axum::body::Bytes) -> Response {
    probe.calls.fetch_add(1, Ordering::SeqCst);
    *probe.body.lock().unwrap() = serde_json::from_slice(&body).ok();
    match probe.mode {
        1 => (StatusCode::INTERNAL_SERVER_ERROR, "PRIVATE-ERROR-CANARY").into_response(),
        2 => (StatusCode::OK, "x".repeat(9000)).into_response(),
        3 => (StatusCode::OK, "PRIVATE-NONJSON-CANARY").into_response(),
        4 => (
            StatusCode::TEMPORARY_REDIRECT,
            [(axum::http::header::LOCATION, probe.redirect.clone().unwrap())],
        ).into_response(),
        5 => {
            sleep(Duration::from_millis(80)).await;
            Json(json!({"choices": [{"message": {"content": "synthetic"}}]})).into_response()
        }
        6 => Json(json!({"choices": [{"message": {"content": "x".repeat(5000)}}]})).into_response(),
        _ => Json(json!({"choices": [{"message": {"content": "synthetic"}}]})).into_response(),
    }
}

struct FixtureVerifier {
    calls: Arc<AtomicUsize>,
    mode: u8,
}

#[async_trait::async_trait]
impl ZkVerifier for FixtureVerifier {
    async fn verify(&self, ticket: &ZkTicket, context: &VerificationContext)
        -> std::result::Result<VerifiedTicket, ZkVerifyError>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode == 1 { return Err(ZkVerifyError::InvalidProof); }
        if self.mode == 2 { return Err(ZkVerifyError::Internal("PRIVATE-VERIFIER-CANARY".into())); }
        if ticket.commitment_root.0 != context.request_commitment {
            return Err(ZkVerifyError::InvalidProof);
        }
        Ok(VerifiedTicket {
            token_class: if self.mode == 3 { TokenClass::C512 } else { ticket.token_class },
            nullifier_key: replay_key(ticket),
        })
    }
}

struct Harness {
    gateway: Server,
    _upstream: Server,
    state: Arc<AppState>,
    probe: Arc<Probe>,
    verifier_calls: Arc<AtomicUsize>,
    client: reqwest::Client,
}

async fn harness(compatibility: bool, upstream_mode: u8, verifier_mode: u8, redirect: Option<String>) -> Harness {
    let probe = Arc::new(Probe {
        calls: AtomicUsize::new(0), body: Mutex::new(None), mode: upstream_mode, redirect,
    });
    let upstream = serve(Router::new()
        .route("/v1/chat/completions", post(upstream))
        .route("/v1/models", get(upstream))
        .with_state(probe.clone())).await;
    let verifier_calls = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(AppState {
        keypair: GatewayKeypair::generate(),
        verifier: Arc::new(FixtureVerifier { calls: verifier_calls.clone(), mode: verifier_mode }),
        nullifier_db: sled::Config::new().temporary(true).open().unwrap(),
        http: provider_http_client(Duration::from_secs(2)).unwrap(),
        provider_base_url: upstream.url.clone(), provider_api_key: Some("synthetic-provider-credential".into()),
        privacy_jitter_ms: 0, privacy_min_response_delay_ms: 0,
        nullifier_pending_ttl_ms: 0, compatibility_enabled: compatibility,
    });
    let gateway = serve(build_router(state.clone())).await;
    Harness { gateway, _upstream: upstream, state, probe, verifier_calls,
        client: provider_http_client(Duration::from_secs(3)).unwrap() }
}

fn request() -> InferenceRequest {
    let mut request: InferenceRequest = serde_json::from_value(json!({
        "request_id": Uuid::new_v4(), "model": "synthetic-model",
        "messages": [{"role": "user", "content": "synthetic source"}],
        "max_tokens": null, "temperature": null, "stream": false, "token_class": "c256",
        "ticket": {"commitment_root": "", "nullifier": B64.encode(Uuid::new_v4().as_bytes()),
                   "token_class": "c256", "proof": B64.encode(b"SYNTHETIC-NOT-FINALITY")},
    })).unwrap();
    bind(&mut request);
    request
}

fn bind(request: &mut InferenceRequest) {
    request.ticket.commitment_root = B64Bytes(request.authorization_commitment().unwrap());
}

fn seal(h: &Harness, request: &InferenceRequest) -> (Envelope, ClientCryptoContext) {
    seal_request_for_gateway(h.state.keypair.public_bytes(), request.token_class,
        request.request_id, &serde_json::to_vec(request).unwrap()).unwrap()
}

async fn post_envelope(h: &Harness, env: &Envelope, context: &ClientCryptoContext) -> Value {
    let response = h.client.post(format!("{}/v1/infer", h.gateway.url))
        .json(env).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let envelope: Envelope = response.json().await.unwrap();
    serde_json::from_slice(&context.open_response(&envelope).unwrap()).unwrap()
}

async fn send(h: &Harness, request: &InferenceRequest) -> Value {
    let (env, context) = seal(h, request);
    post_envelope(h, &env, &context).await
}

fn calls(h: &Harness) -> usize { h.probe.calls.load(Ordering::SeqCst) }

#[test]
fn compatibility_mode_is_explicit_and_dummy_only() {
    let local = "127.0.0.1:8080".parse().unwrap();
    let remote = "0.0.0.0:8080".parse().unwrap();
    for kind in [ZkVerifierKind::Actum, ZkVerifierKind::Halo2] {
        assert!(!is_compat_mode_allowed(true, kind, true, local, true));
        assert!(is_compat_mode_allowed(false, kind, false, remote, false));
    }
    assert!(!is_compat_mode_allowed(true, ZkVerifierKind::Dummy, false, local, false));
    assert!(!is_compat_mode_allowed(true, ZkVerifierKind::Dummy, true, remote, false));
    assert!(is_compat_mode_allowed(true, ZkVerifierKind::Dummy, true, local, false));
    assert!(is_compat_mode_allowed(true, ZkVerifierKind::Dummy, true, remote, true));
}

#[tokio::test]
async fn default_router_has_no_unpaid_routes() {
    let h = harness(false, 0, 0, None).await;
    for path in ["/v1/chat/completions", "/v1/chat/completions/", "/v1/responses"] {
        let response = h.client.post(format!("{}{path}", h.gateway.url)).json(&json!({}))
            .send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(h.client.get(format!("{}/v1/models", h.gateway.url)).send().await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(calls(&h), 0);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn compatibility_handler_cannot_bypass_disabled_router_policy() {
    let h = harness(false, 0, 0, None).await;
    assert_eq!(compat_proxy(&h.state, Method::POST, "/v1/chat/completions", Some(json!({}))).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(calls(&h), 0);
}

#[tokio::test]
async fn explicit_demo_compatibility_positive_control() {
    let h = harness(true, 0, 0, None).await;
    let response = h.client.post(format!("{}/v1/chat/completions", h.gateway.url))
        .json(&json!({"model":"synthetic","messages":[]})).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls(&h), 1);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn paid_positive_control_and_replay_refusal() {
    let h = harness(false, 0, 0, None).await;
    let request = request();
    assert_eq!(send(&h, &request).await["kind"], "ok");
    assert_eq!(send(&h, &request).await["error"]["code"], "double_spend");
    assert_eq!(calls(&h), 1);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 2);
    let provider_request = h.probe.body.lock().unwrap().clone().unwrap();
    assert_eq!(provider_request["max_tokens"], 256);
    assert!(provider_request.get("ticket").is_none());
    assert!(provider_request.get("request_id").is_none());
}

#[tokio::test]
async fn identity_mismatch_denied_before_verifier_and_spend() {
    let h = harness(false, 0, 0, None).await;
    let request = request();
    let outer_id = Uuid::new_v4();
    let (env, context) = seal_request_for_gateway(h.state.keypair.public_bytes(), TokenClass::C256,
        outer_id, &serde_json::to_vec(&request).unwrap()).unwrap();
    let response = post_envelope(&h, &env, &context).await;
    assert_eq!(response["error"]["code"], "request_id_mismatch");
    assert_eq!(response["error"]["request_id"], outer_id.to_string());
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls(&h), 0);
    assert!(h.state.nullifier_db.is_empty());
}

#[tokio::test]
async fn decryptable_bad_json_returns_encrypted_data_free_error() {
    let h = harness(false, 0, 0, None).await;
    let id = Uuid::new_v4();
    let (env, context) = seal_request_for_gateway(h.state.keypair.public_bytes(), TokenClass::C256,
        id, br#"{"patient":"PRIVATE-PARSE-CANARY","token_class":"SECRET"}"#).unwrap();
    let response = post_envelope(&h, &env, &context).await;
    assert_eq!(response["error"]["code"], "invalid_request");
    assert!(!response.to_string().contains("PRIVATE-PARSE-CANARY"));
    assert_eq!(calls(&h), 0);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn encrypted_input_size_mismatch_is_rejected_before_verification() {
    let h = harness(false, 0, 0, None).await;
    let (mut env, _) = seal(&h, &request());
    env.ciphertext_b64 = B64.encode([0_u8; 16]);
    let response = h.client.post(format!("{}/v1/infer", h.gateway.url)).json(&env).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(calls(&h), 0);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reserved_options_and_multiple_completion_requests_are_refused() {
    let h = harness(false, 0, 0, None).await;
    for (key, value) in [
        ("max_completion_tokens", json!(999999)), ("max_output_tokens", json!(999999)),
        ("provider_options", json!({"model":"other"})), ("n", json!(2)), ("store", json!(true)),
    ] {
        let mut request = request();
        request.provider_options.insert(key.into(), value);
        bind(&mut request);
        assert_eq!(send(&h, &request).await["kind"], "err");
    }
    assert_eq!(calls(&h), 0);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn supported_options_are_preserved() {
    let h = harness(false, 0, 0, None).await;
    let mut request = request();
    request.provider_options.insert("n".into(), json!(1));
    request.provider_options.insert("store".into(), json!(false));
    request.provider_options.insert("response_format".into(), json!({"type":"json_object"}));
    bind(&mut request);
    assert_eq!(send(&h, &request).await["kind"], "ok");
    let sent = h.probe.body.lock().unwrap().clone().unwrap();
    assert_eq!(sent["n"], 1);
    assert_eq!(sent["store"], false);
    assert_eq!(sent["response_format"]["type"], "json_object");
}

#[tokio::test]
async fn verifier_denial_unavailability_or_wrong_class_never_dispatch() {
    for mode in [1, 2, 3] {
        let h = harness(false, 0, mode, None).await;
        assert_eq!(send(&h, &request()).await["kind"], "err");
        assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls(&h), 0);
        assert!(h.state.nullifier_db.is_empty());
    }
}

#[tokio::test]
async fn upstream_error_invalid_json_and_oversize_preserve_reservation() {
    for mode in [1, 2, 3] {
        let h = harness(false, mode, 0, None).await;
        let request = request();
        let response = send(&h, &request).await;
        assert_eq!(response["kind"], "err");
        assert!(!response.to_string().contains("PRIVATE-"));
        assert_eq!(send(&h, &request).await["error"]["code"], "double_spend");
        assert_eq!(calls(&h), 1);
        assert!(h.state.nullifier_db.contains_key(replay_key(&request.ticket)).unwrap());
    }
}

#[tokio::test]
async fn wrapped_response_overflow_is_encrypted_without_refund_or_retry() {
    let h = harness(false, 6, 0, None).await;
    let request = request();
    assert_eq!(send(&h, &request).await["error"]["code"], "response_too_large");
    assert_eq!(send(&h, &request).await["error"]["code"], "double_spend");
    assert_eq!(calls(&h), 1);
}

#[tokio::test]
async fn concurrent_duplicate_has_only_one_upstream_invocation() {
    let h = harness(false, 5, 0, None).await;
    let request = request();
    let (left, right) = tokio::join!(send(&h, &request), send(&h, &request));
    assert!(left["kind"] == "ok" || right["kind"] == "ok");
    assert!(left["kind"] == "err" || right["kind"] == "err");
    assert_eq!(calls(&h), 1);
}

#[tokio::test]
async fn upstream_redirect_is_not_followed() {
    let target = harness(false, 0, 0, None).await;
    let h = harness(false, 4, 0, Some(format!("{}/v1/chat/completions", target._upstream.url))).await;
    assert_eq!(send(&h, &request()).await["error"]["code"], "upstream_error");
    assert_eq!(calls(&h), 1);
    assert_eq!(calls(&target), 0);
}

#[tokio::test]
async fn http_body_limit_denies_before_verification() {
    let h = harness(false, 0, 0, None).await;
    let response = h.client.post(format!("{}/v1/infer", h.gateway.url))
        .header("content-type", "application/json").body("x".repeat(129 * 1024)).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(calls(&h), 0);
    assert_eq!(h.verifier_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_and_malformed_existing_replay_records_fail_closed() {
    let db = sled::Config::new().temporary(true).open().unwrap();
    for (i, value) in [b"".to_vec(), b"broken".to_vec(), encode_nullifier_value(b'p', 0), encode_nullifier_value(b'x', 0)].iter().enumerate() {
        let key = [i as u8];
        db.insert(key, value.as_slice()).unwrap();
        assert!(matches!(reserve_nullifier(&db, &key, &encode_nullifier_value(b'p', 9999), 0), Err(ReserveError::AlreadyUsed)));
    }
}
