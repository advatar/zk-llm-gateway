use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, ValueEnum};
use log::{error, info, warn};
use rand::Rng;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::time::sleep;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

use zk_llm_common::{
    envelope::{open_request_at_gateway, seal_response_at_gateway, GatewayKeypair},
    types::{ErrorResponse, GatewayEnvelopePayload, InferenceRequest, InferenceResponse},
    zk::{replay_key, DummyVerifier, ZkVerifier, ZkVerifyError},
};

use zk_llm_verifier_halo2::{Halo2PlonkVerifier, Halo2PlonkVerifierConfig};

#[derive(Parser, Debug)]
#[command(name = "zk-llm-gateway")]
struct Cli {
    /// Listen address for the gateway (e.g. 0.0.0.0:8080)
    #[arg(long, env = "GATEWAY_LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    listen_addr: String,

    /// Base64-encoded 32-byte X25519 secret key used to decrypt envelopes.
    ///
    /// Generate a keypair using `--generate-keys`.
    #[arg(long, env = "GATEWAY_SECRET_KEY_B64")]
    gateway_secret_key_b64: Option<String>,

    /// Print a newly generated gateway keypair (base64) and exit.
    #[arg(long)]
    generate_keys: bool,

    /// Sled DB path for nullifier/replay protection.
    #[arg(long, env = "GATEWAY_DB_PATH", default_value = "./gateway-db")]
    db_path: String,

    /// Allow the insecure dummy ZK verifier (dev only).
    #[arg(long, env = "GATEWAY_ALLOW_DUMMY_VERIFIER", default_value_t = false)]
    allow_dummy_verifier: bool,

    /// Which ZK verifier to use.
    /// - dummy: insecure, dev-only
    /// - halo2: Halo2/Plonk verifier (skeleton; circuit-specific)
    #[arg(long, env = "GATEWAY_ZK_VERIFIER", value_enum, default_value = "dummy")]
    zk_verifier: ZkVerifierKind,

    /// Path to a Halo2 verifying key file (required if --zk-verifier halo2)
    #[arg(long, env = "HALO2_VK_PATH")]
    halo2_vk_path: Option<String>,

    /// Optional path to Halo2 params (KZG/IPA) file.
    #[arg(long, env = "HALO2_PARAMS_PATH")]
    halo2_params_path: Option<String>,

    /// Upstream model provider base URL (OpenAI-compatible).
    #[arg(
        long,
        env = "PROVIDER_BASE_URL",
        default_value = "http://localhost:8000"
    )]
    provider_base_url: String,

    /// Upstream provider API key (if required)
    #[arg(long, env = "PROVIDER_API_KEY")]
    provider_api_key: Option<String>,

    /// Request timeout (ms) to upstream provider.
    #[arg(long, env = "PROVIDER_TIMEOUT_MS", default_value_t = 120_000)]
    provider_timeout_ms: u64,

    /// Maximum additional random delay (ms) before sending encrypted responses.
    ///
    /// This is a *best-effort* mitigation against timing correlation by observers/relays.
    #[arg(long, env = "PRIVACY_JITTER_MS", default_value_t = 0)]
    privacy_jitter_ms: u64,

    /// Minimum response time (ms) before sending encrypted responses.
    ///
    /// This is a best-effort mitigation against timing correlation by observers/relays.
    #[arg(long, env = "PRIVACY_MIN_RESPONSE_DELAY_MS", default_value_t = 0)]
    privacy_min_response_delay_ms: u64,

    /// How long a "pending" nullifier reservation may live before being considered stale.
    ///
    /// This lets clients retry if the gateway crashes mid-request.
    #[arg(long, env = "NULLIFIER_PENDING_TTL_MS", default_value_t = 300_000)]
    nullifier_pending_ttl_ms: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum ZkVerifierKind {
    Dummy,
    Halo2,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    if cli.generate_keys {
        let kp = GatewayKeypair::generate();
        let sk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.secret_bytes());
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_bytes());
        println!("GATEWAY_SECRET_KEY_B64={}", sk_b64);
        println!("GATEWAY_PUBLIC_KEY_B64={}", pk_b64);
        return Ok(());
    }

    let secret_b64 = cli
        .gateway_secret_key_b64
        .clone()
        .context("GATEWAY_SECRET_KEY_B64 is required (or use --generate-keys)")?;
    let secret_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(secret_b64)
        .context("invalid base64 in GATEWAY_SECRET_KEY_B64")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("GATEWAY_SECRET_KEY_B64 must decode to 32 bytes"))?;

    let keypair = GatewayKeypair::from_secret_bytes(secret_bytes);
    info!(
        "gateway public key (base64): {}",
        base64::engine::general_purpose::STANDARD.encode(keypair.public_bytes())
    );

    let db = sled::open(&cli.db_path).context("failed to open sled db")?;

    let verifier: Arc<dyn ZkVerifier> = match cli.zk_verifier {
        ZkVerifierKind::Dummy => {
            if cli.allow_dummy_verifier {
                warn!("USING INSECURE DUMMY VERIFIER (dev mode)");
                Arc::new(DummyVerifier::default())
            } else {
                return Err(anyhow::anyhow!(
                    "dummy verifier selected but disabled. For dev: set GATEWAY_ALLOW_DUMMY_VERIFIER=true"
                ));
            }
        }
        ZkVerifierKind::Halo2 => {
            let vk_path = cli
                .halo2_vk_path
                .clone()
                .context("HALO2_VK_PATH is required when --zk-verifier halo2")?;
            let cfg = Halo2PlonkVerifierConfig {
                verifying_key_path: vk_path.into(),
                params_path: cli.halo2_params_path.clone().map(Into::into),
            };
            let v = Halo2PlonkVerifier::new(cfg).context("init halo2 verifier")?;
            Arc::new(v)
        }
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(cli.provider_timeout_ms))
        .build()
        .context("failed to build reqwest client")?;

    let state = Arc::new(AppState {
        keypair,
        verifier,
        nullifier_db: db,
        http,
        provider_base_url: cli.provider_base_url,
        provider_api_key: cli.provider_api_key,
        privacy_jitter_ms: cli.privacy_jitter_ms,
        privacy_min_response_delay_ms: cli.privacy_min_response_delay_ms,
        nullifier_pending_ttl_ms: cli.nullifier_pending_ttl_ms,
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/models", get(compat_models))
        .route("/v1/chat/completions", post(compat_chat_completions))
        .route("/v1/infer", post(infer))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cli
        .listen_addr
        .parse()
        .context("invalid GATEWAY_LISTEN_ADDR")?;

    info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize)]
struct GatewayPubkeyResponse {
    public_key_b64: String,
}

async fn pubkey(State(state): State<Arc<AppState>>) -> Json<GatewayPubkeyResponse> {
    Json(GatewayPubkeyResponse {
        public_key_b64: B64.encode(state.keypair.public_bytes()),
    })
}

async fn compat_models(State(state): State<Arc<AppState>>) -> Response {
    compat_proxy(&state, Method::GET, "/v1/models", None).await
}

async fn compat_chat_completions(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Response {
    compat_proxy(&state, Method::POST, "/v1/chat/completions", Some(body)).await
}

async fn compat_proxy(
    state: &AppState,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Response {
    let mut builder = state
        .http
        .request(method, provider_url(&state.provider_base_url, path));
    if let Some(key) = &state.provider_api_key {
        builder = builder.bearer_auth(key);
    }
    if let Some(body) = body {
        builder = builder.json(&body);
    }

    let resp = match builder.send().await {
        Ok(resp) => resp,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {
                        "code": "upstream_unreachable",
                        "message": "upstream network error"
                    }
                })),
            )
                .into_response();
        }
    };

    let status = resp.status();
    let bytes = match resp.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {
                        "code": "upstream_unreachable",
                        "message": "upstream read error"
                    }
                })),
            )
                .into_response();
        }
    };

    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => (status, Json(value)).into_response(),
        Err(_) => (
            status,
            Json(json!({
                "raw": String::from_utf8_lossy(&bytes),
            })),
        )
            .into_response(),
    }
}

struct AppState {
    keypair: GatewayKeypair,
    verifier: Arc<dyn ZkVerifier>,
    nullifier_db: sled::Db,
    http: reqwest::Client,
    provider_base_url: String,
    provider_api_key: Option<String>,
    privacy_jitter_ms: u64,
    privacy_min_response_delay_ms: u64,
    nullifier_pending_ttl_ms: u64,
}

/// Envelope request handler.
///
/// Expects JSON body of `Envelope` (encrypted). Returns JSON `Envelope` (encrypted).
async fn infer(
    State(state): State<Arc<AppState>>,
    Json(env): Json<zk_llm_common::envelope::Envelope>,
) -> Result<Json<zk_llm_common::envelope::Envelope>, ApiError> {
    let started = std::time::Instant::now();
    // Step 1: decrypt. If we can't decrypt, we cannot respond encrypted.
    let plaintext = open_request_at_gateway(&state.keypair, &env)
        .map_err(|e| ApiError::bad_request(None, "decrypt_failed", format!("{}", e)))?;

    let req: InferenceRequest = serde_json::from_slice(&plaintext)
        .map_err(|e| ApiError::bad_request(None, "invalid_json", format!("{}", e)))?;

    infer_canonical(state, env, req, started).await
}

async fn infer_canonical(
    state: Arc<AppState>,
    env: zk_llm_common::envelope::Envelope,
    req: InferenceRequest,
    started: std::time::Instant,
) -> Result<Json<zk_llm_common::envelope::Envelope>, ApiError> {
    // From here on, we can return encrypted errors.
    let result: Result<ProviderChatCompletionResult, EncryptedError> = async {
        // Consistency checks to reduce cross-protocol confusion
        if req.token_class != env.token_class {
            return Err(EncryptedError::bad_request(
                req.request_id,
                "token_class_mismatch",
                "request token_class does not match envelope",
            ));
        }
        if req.ticket.token_class != req.token_class {
            return Err(EncryptedError::bad_request(
                req.request_id,
                "token_class_mismatch",
                "ticket token_class does not match request",
            ));
        }

        // Coarse prompt sizing check (bytes approximation).
        // This is not a perfect token counter, but it is a cheap guardrail to keep
        // requests within the intended bucket.
        if approx_prompt_bytes(&req.messages) > req.token_class.max_prompt_bytes() {
            return Err(EncryptedError::bad_request(
                req.request_id,
                "prompt_too_large",
                "prompt exceeds token-class size limit",
            ));
        }

        if req.stream == Some(true) {
            return Err(EncryptedError::bad_request(
                req.request_id,
                "stream_unsupported",
                "stream=true is not supported on /v1/infer",
            ));
        }

        // Verify ZK ticket
        let _verified = state
            .verifier
            .verify(&req.ticket)
            .map_err(|e| map_zk_error(req.request_id, e))?;

        // Replay protection: reserve the nullifier before calling the provider.
        //
        // We keep a small "pending" state so a crash mid-request doesn't permanently brick a ticket.
        let rkey = replay_key(&req.ticket);
        let pending_val = encode_nullifier_value(b'p', now_ms_u64());
        reserve_nullifier(
            &state.nullifier_db,
            &rkey,
            &pending_val,
            state.nullifier_pending_ttl_ms,
        )
        .map_err(|e| match e {
            ReserveError::AlreadyUsed => EncryptedError::payment_required(
                req.request_id,
                "double_spend",
                "ticket nullifier already used",
            ),
            ReserveError::Db => EncryptedError::internal(req.request_id, "db error"),
        })?;

        // Forward request to provider
        let provider_response = match call_provider(&state, &req).await {
            Ok(response) => response,
            Err(e) => {
                // Best-effort: release pending reservation to allow retry.
                let _ = state.nullifier_db.compare_and_swap(
                    &rkey,
                    Some(pending_val.as_slice()),
                    None as Option<&[u8]>,
                );
                return Err(e);
            }
        };

        // Mark as spent.
        let spent_val = encode_nullifier_value(b's', now_ms_u64());
        let _ = state.nullifier_db.insert(&rkey, spent_val.as_slice());

        // (Optional) You can implement additional output shaping/padding here.
        // We avoid modifying model outputs in v1 to preserve semantics.

        // Build response
        Ok(provider_response)
    }
    .await;

    // Convert to encrypted payload
    let payload = match result {
        Ok(provider_response) => {
            let resp = InferenceResponse {
                request_id: req.request_id,
                model: req.model.clone(),
                output: provider_response.output,
                billed_token_class: req.token_class,
                upstream: Some(provider_response.body),
            };
            GatewayEnvelopePayload::Ok { response: resp }
        }
        Err(e) => GatewayEnvelopePayload::Err {
            error: ErrorResponse {
                request_id: Some(req.request_id),
                code: e.code.to_string(),
                message: e.message.to_string(),
            },
        },
    };

    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| ApiError::internal(Some(req.request_id), format!("serialize: {}", e)))?;

    finalize_encrypted_response(&state, &env, payload_json, started, Some(req.request_id)).await
}

async fn finalize_encrypted_response(
    state: &AppState,
    req_env: &zk_llm_common::envelope::Envelope,
    payload_json: Vec<u8>,
    started: std::time::Instant,
    request_id: Option<Uuid>,
) -> Result<Json<zk_llm_common::envelope::Envelope>, ApiError> {
    // Best-effort timing padding (does not affect provider, only relay / network observers)
    if state.privacy_min_response_delay_ms > 0 {
        let elapsed = started.elapsed();
        let min = Duration::from_millis(state.privacy_min_response_delay_ms);
        if elapsed < min {
            sleep(min - elapsed).await;
        }
    }

    // Optional response jitter (adds random noise on top)
    if state.privacy_jitter_ms > 0 {
        let delay = rand::thread_rng().gen_range(0..=state.privacy_jitter_ms);
        sleep(Duration::from_millis(delay)).await;
    }

    let resp_env = seal_response_at_gateway(&state.keypair, req_env, &payload_json)
        .map_err(|e| ApiError::internal(request_id, format!("encrypt: {}", e)))?;

    Ok(Json(resp_env))
}

fn provider_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[derive(Debug)]
struct EncryptedError {
    code: &'static str,
    message: &'static str,
}

impl EncryptedError {
    fn bad_request(request_id: uuid::Uuid, code: &'static str, message: &'static str) -> Self {
        let _ = request_id; // reserved for future expansion
        Self { code, message }
    }

    fn payment_required(request_id: uuid::Uuid, code: &'static str, message: &'static str) -> Self {
        let _ = request_id;
        Self { code, message }
    }

    fn upstream(request_id: uuid::Uuid, code: &'static str, message: &'static str) -> Self {
        let _ = request_id;
        Self { code, message }
    }

    fn internal(request_id: uuid::Uuid, message: &str) -> Self {
        let _ = request_id;
        // Coarsen internal details
        let _ = message;
        Self {
            code: "internal_error",
            message: "internal error",
        }
    }
}

fn map_zk_error(request_id: uuid::Uuid, err: ZkVerifyError) -> EncryptedError {
    match err {
        ZkVerifyError::InvalidProof => {
            EncryptedError::payment_required(request_id, "invalid_proof", "invalid usage proof")
        }
        ZkVerifyError::Internal(_msg) => EncryptedError::internal(request_id, "verifier error"),
    }
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("bad request")]
    BadRequest(ErrorResponse),
    #[error("internal error")]
    Internal(ErrorResponse),
}

impl ApiError {
    fn bad_request(request_id: Option<uuid::Uuid>, code: &str, message: String) -> Self {
        ApiError::BadRequest(ErrorResponse {
            request_id,
            code: code.to_string(),
            message,
        })
    }

    fn internal(request_id: Option<uuid::Uuid>, message: String) -> Self {
        ApiError::Internal(ErrorResponse {
            request_id,
            code: "internal_error".to_string(),
            message,
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, err) = match self {
            ApiError::BadRequest(e) => (StatusCode::BAD_REQUEST, e),
            ApiError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        // Privacy note: we intentionally do not include upstream bodies, prompts, etc.
        (status, Json(err)).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ProviderChatCompletionRequest {
    model: String,
    messages: Vec<zk_llm_common::types::ChatMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug)]
struct ProviderChatCompletionResult {
    body: Value,
    output: String,
}

async fn call_provider(
    state: &AppState,
    req: &InferenceRequest,
) -> Result<ProviderChatCompletionResult, EncryptedError> {
    // Clamp output length to token class
    // Privacy choice: ignore client-provided max_tokens and always use the class maximum.
    // This coarsens metadata visible to the upstream provider.
    let max_tokens = req.token_class.max_completion_tokens();

    let body = ProviderChatCompletionRequest {
        model: req.model.clone(),
        messages: req.messages.clone(),
        max_tokens,
        temperature: req.temperature,
        stream: req.stream,
        extra: req.provider_options.clone(),
    };

    let url = format!(
        "{}/v1/chat/completions",
        state.provider_base_url.trim_end_matches('/')
    );

    let mut builder = state.http.post(url).json(&body);
    if let Some(key) = &state.provider_api_key {
        builder = builder.bearer_auth(key);
    }

    let resp = builder.send().await.map_err(|_e| {
        EncryptedError::upstream(req.request_id, "upstream_network", "upstream network error")
    })?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|_e| {
        EncryptedError::upstream(req.request_id, "upstream_read", "upstream read error")
    })?;

    if !status.is_success() {
        // Do not pass through upstream body verbatim (may contain sensitive content).
        warn!(
            "upstream error status={} request_id={} body_len={}",
            status,
            req.request_id,
            bytes.len()
        );
        return Err(EncryptedError::upstream(
            req.request_id,
            "upstream_error",
            "upstream returned error",
        ));
    }

    let body: Value = serde_json::from_slice(&bytes).map_err(|e| {
        error!("failed to parse upstream response: {}", e);
        EncryptedError::upstream(req.request_id, "upstream_parse", "upstream parse error")
    })?;

    Ok(ProviderChatCompletionResult {
        output: extract_provider_output(&body),
        body,
    })
}

fn approx_prompt_bytes(messages: &[zk_llm_common::types::ChatMessage]) -> usize {
    serde_json::to_vec(messages)
        .map(|bytes| bytes.len())
        .unwrap_or_else(|_| messages.iter().map(|m| m.role.len() + m.content.len()).sum())
}

#[derive(Debug)]
enum ReserveError {
    AlreadyUsed,
    Db,
}

fn encode_nullifier_value(status: u8, ts_ms: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    v.push(status);
    v.extend_from_slice(&ts_ms.to_be_bytes());
    v
}

fn extract_provider_output(body: &Value) -> String {
    let content = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"));

    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn decode_nullifier_value(v: &[u8]) -> Option<(u8, u64)> {
    if v.len() != 9 {
        return None;
    }
    let status = v[0];
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&v[1..9]);
    Some((status, u64::from_be_bytes(ts)))
}

fn reserve_nullifier(
    db: &sled::Db,
    rkey: &[u8],
    pending_val: &[u8],
    pending_ttl_ms: u64,
) -> std::result::Result<(), ReserveError> {
    // Fast path: reserve if absent.
    let cas = db
        .compare_and_swap(rkey, None as Option<&[u8]>, Some(pending_val))
        .map_err(|_| ReserveError::Db)?;
    if cas.is_ok() {
        return Ok(());
    }

    // Slow path: check if existing reservation is stale pending.
    let existing = db.get(rkey).map_err(|_| ReserveError::Db)?;
    if let Some(val) = existing {
        if let Some((status, ts)) = decode_nullifier_value(val.as_ref()) {
            if status == b'p' {
                let now = now_ms_u64();
                if now.saturating_sub(ts) > pending_ttl_ms {
                    // Attempt to clear stale pending.
                    let _ = db
                        .compare_and_swap(rkey, Some(val.as_ref()), None as Option<&[u8]>)
                        .map_err(|_| ReserveError::Db)?;
                    // Try again.
                    let cas2 = db
                        .compare_and_swap(rkey, None as Option<&[u8]>, Some(pending_val))
                        .map_err(|_| ReserveError::Db)?;
                    if cas2.is_ok() {
                        return Ok(());
                    }
                }
            }
        }
    }

    Err(ReserveError::AlreadyUsed)
}

fn now_ms_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() * 1000) + (d.subsec_millis() as u64)
}
