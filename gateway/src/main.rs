use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, ValueEnum};
use log::{info, warn};
use rand::Rng;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::time::sleep;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use zk_llm_common::{
    envelope::{open_request_at_gateway, seal_response_at_gateway, GatewayKeypair},
    types::{ErrorResponse, GatewayEnvelopePayload, InferenceRequest, InferenceResponse},
    zk::{replay_key, DummyVerifier, VerificationContext, ZkVerifier, ZkVerifyError},
};

use zk_llm_verifier_halo2::{Halo2PlonkVerifier, Halo2PlonkVerifierConfig};

mod actum;
use actum::ActumVerifier;

mod admission;
use admission::{check_envelope_size, check_request, read_bounded_body};

#[cfg(test)]
mod admission_tests;

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

    /// Allow the insecure dummy verifier to bind non-loopback addresses for local Docker demos.
    ///
    /// This is still dev-only. It exists so a container can listen on its Docker bridge interface
    /// while the host publishes the port on localhost.
    #[arg(
        long,
        env = "GATEWAY_ALLOW_DUMMY_NON_LOOPBACK_LOCAL_DEMO",
        default_value_t = false
    )]
    allow_dummy_non_loopback_local_demo: bool,

    /// Enable unpaid compatibility routes for isolated dummy-verifier demos only.
    /// Never allowed with Actum or Halo2. Off by default, including Docker demos.
    #[arg(long, env = "GATEWAY_ENABLE_COMPAT_LOCAL_DEMO", default_value_t = false)]
    enable_compat_local_demo: bool,

    /// Which ZK verifier to use.
    /// - dummy: insecure, dev-only
    /// - halo2: Halo2/Plonk verifier (skeleton; circuit-specific)
    #[arg(long, env = "GATEWAY_ZK_VERIFIER", value_enum)]
    zk_verifier: Option<ZkVerifierKind>,

    /// Path to a Halo2 verifying key file (required if --zk-verifier halo2)
    #[arg(long, env = "HALO2_VK_PATH")]
    halo2_vk_path: Option<String>,

    /// Optional path to Halo2 params (KZG/IPA) file.
    #[arg(long, env = "HALO2_PARAMS_PATH")]
    halo2_params_path: Option<String>,

    /// Actum verifier endpoint implementing the actum.payment-finality.v1 contract.
    #[arg(long, env = "ACTUM_VERIFIER_URL")]
    actum_verifier_url: Option<String>,

    /// Bearer credential used only between the gateway and Actum verifier.
    #[arg(long, env = "ACTUM_VERIFIER_BEARER_TOKEN")]
    actum_verifier_bearer_token: Option<String>,

    /// Actum audience/merchant binding expected in payment authorization.
    #[arg(long, env = "ACTUM_AUDIENCE")]
    actum_audience: Option<String>,

    /// Allow plain HTTP to the Actum verifier for an isolated Docker-local network.
    #[arg(
        long,
        env = "ACTUM_ALLOW_INSECURE_HTTP_LOCAL_DEV",
        default_value_t = false
    )]
    actum_allow_insecure_http_local_dev: bool,

    /// Actum verification request timeout.
    #[arg(long, env = "ACTUM_VERIFIER_TIMEOUT_MS", default_value_t = 10_000)]
    actum_verifier_timeout_ms: u64,

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
    #[arg(long, env = "PRIVACY_JITTER_MS", default_value_t = 250)]
    privacy_jitter_ms: u64,

    /// Minimum response time (ms) before sending encrypted responses.
    ///
    /// This is a best-effort mitigation against timing correlation by observers/relays.
    #[arg(long, env = "PRIVACY_MIN_RESPONSE_DELAY_MS", default_value_t = 250)]
    privacy_min_response_delay_ms: u64,

    /// Deprecated compatibility setting; ignored. Reservations no longer expire.
    /// A timeout or process failure cannot establish that provider work did not happen.
    #[arg(long, env = "NULLIFIER_PENDING_TTL_MS", default_value_t = 300_000)]
    nullifier_pending_ttl_ms: u64,

    /// Comma-separated browser origins allowed to call the gateway.
    #[arg(
        long,
        env = "GATEWAY_CORS_ALLOWED_ORIGINS",
        default_value = "http://localhost:3000,http://127.0.0.1:3000"
    )]
    cors_allowed_origins: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum ZkVerifierKind {
    Dummy,
    Halo2,
    Actum,
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

    let addr: SocketAddr = cli
        .listen_addr
        .parse()
        .context("invalid GATEWAY_LISTEN_ADDR")?;

    let zk_verifier = cli.zk_verifier.context(
        "GATEWAY_ZK_VERIFIER is required. Actum delegates payment verification; halo2 is a rejecting skeleton and dummy is development only",
    )?;

    if matches!(zk_verifier, ZkVerifierKind::Dummy)
        && !is_dummy_bind_allowed(addr, cli.allow_dummy_non_loopback_local_demo)
    {
        return Err(anyhow::anyhow!(
            "refusing to bind {} with insecure dummy verifier; use a loopback listen address or configure a real verifier",
            addr
        ));
    }
    if matches!(zk_verifier, ZkVerifierKind::Dummy)
        && cli.allow_dummy_non_loopback_local_demo
        && !addr.ip().is_loopback()
    {
        warn!("USING INSECURE DUMMY VERIFIER ON NON-LOOPBACK BIND FOR LOCAL DOCKER DEMO ONLY");
    }

    if !is_compat_mode_allowed(
        cli.enable_compat_local_demo,
        zk_verifier,
        cli.allow_dummy_verifier,
        addr,
        cli.allow_dummy_non_loopback_local_demo,
    ) {
        anyhow::bail!("compatibility routes require an explicitly enabled isolated dummy-verifier demo");
    }
    if cli.enable_compat_local_demo {
        warn!("UNPAID COMPATIBILITY ROUTES ENABLED FOR ISOLATED LOCAL DEMO ONLY");
    }

    let db = sled::open(&cli.db_path).context("failed to open sled db")?;

    let verifier: Arc<dyn ZkVerifier> = match zk_verifier {
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
            warn!(
                "halo2 verifier selected, but the shipped circuit is a non-functional skeleton: \
                 it rejects ALL tickets until a real proof verifier is wired in. The gateway will \
                 start and report healthy, but every /v1/infer request will fail verification."
            );
            Arc::new(v)
        }
        ZkVerifierKind::Actum => Arc::new(
            ActumVerifier::new(
                cli.actum_verifier_url
                    .as_deref()
                    .context("ACTUM_VERIFIER_URL is required when --zk-verifier actum")?,
                cli.actum_verifier_bearer_token
                    .clone()
                    .context("ACTUM_VERIFIER_BEARER_TOKEN is required when --zk-verifier actum")?,
                cli.actum_audience
                    .clone()
                    .context("ACTUM_AUDIENCE is required when --zk-verifier actum")?,
                Duration::from_millis(cli.actum_verifier_timeout_ms),
                cli.actum_allow_insecure_http_local_dev,
            )
            .context("init Actum verifier")?,
        ),
    };

    let http = provider_http_client(Duration::from_millis(cli.provider_timeout_ms))?;

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
        compatibility_enabled: cli.enable_compat_local_demo,
    });

    let cors = cors_layer(&cli.cors_allowed_origins)?;

    let app = build_router(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

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

fn provider_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .context("failed to build provider client")
}

fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/infer", post(infer));
    if state.compatibility_enabled {
        router = router
            .route("/v1/models", get(compat_models))
            .route("/v1/chat/completions", post(compat_chat_completions));
    }
    // Largest v2 class is 68 KiB before AEAD/base64 plus small envelope fields.
    router
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(state)
}

fn is_compat_mode_allowed(
    enabled: bool,
    verifier: ZkVerifierKind,
    allow_dummy: bool,
    addr: SocketAddr,
    allow_docker_demo: bool,
) -> bool {
    !enabled
        || (matches!(verifier, ZkVerifierKind::Dummy)
            && allow_dummy
            && is_dummy_bind_allowed(addr, allow_docker_demo))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn healthz() -> &'static str {
    "ok"
}

fn cors_layer(allowed_origins: &str) -> Result<CorsLayer> {
    let origins = allowed_origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .with_context(|| format!("invalid CORS origin: {}", origin))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION]))
}

fn is_dummy_bind_allowed(addr: SocketAddr, allow_non_loopback_local_demo: bool) -> bool {
    addr.ip().is_loopback() || allow_non_loopback_local_demo
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
    // Defense in depth: a future internal caller must not bypass route registration.
    if !state.compatibility_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut builder = state
        .http
        .request(method, provider_url(&state.provider_base_url, path))
        .header(reqwest::header::ACCEPT_ENCODING, "identity");
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
    if !status.is_success() {
        return (StatusCode::BAD_GATEWAY, Json(json!({"error": {"code": "upstream_error"}})))
            .into_response();
    }
    let bytes = match read_bounded_body(resp, 128 * 1024).await {
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
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": {"code": "upstream_parse"}})),
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
    compatibility_enabled: bool,
}

/// Envelope request handler.
///
/// Expects JSON body of `Envelope` (encrypted). Returns JSON `Envelope` (encrypted).
async fn infer(
    State(state): State<Arc<AppState>>,
    Json(env): Json<zk_llm_common::envelope::Envelope>,
) -> Result<Json<zk_llm_common::envelope::Envelope>, ApiError> {
    let started = std::time::Instant::now();
    // Malformed unauthenticated envelopes get only categorical public errors.
    check_envelope_size(&env).map_err(|code| {
        ApiError::bad_request(None, code, "invalid encrypted envelope".to_string())
    })?;
    let plaintext = open_request_at_gateway(&state.keypair, &env)
        .map_err(|_| ApiError::bad_request(None, "decrypt_failed", "invalid encrypted envelope".to_string()))?;

    let req: InferenceRequest = match serde_json::from_slice(&plaintext) {
        Ok(request) => request,
        Err(_) => {
            let payload = GatewayEnvelopePayload::Err {
                error: ErrorResponse {
                    request_id: Some(env.request_id),
                    code: "invalid_request".into(),
                    message: "invalid inference request".into(),
                },
            };
            let encoded = serde_json::to_vec(&payload)
                .map_err(|_| ApiError::internal(Some(env.request_id), "internal error".into()))?;
            return finalize_encrypted_response(&state, &env, encoded, started, Some(env.request_id)).await;
        }
    };

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
        // Exact request and option policy before verifier, spend or provider I/O.
        check_request(&env, &req).map_err(|code| {
            EncryptedError::bad_request(env.request_id, code, "request policy rejected")
        })?;
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
        let request_commitment = req.authorization_commitment().map_err(|_| {
            EncryptedError::bad_request(
                req.request_id,
                "invalid_request",
                "request cannot be committed",
            )
        })?;
        let verified = state
            .verifier
            .verify(&req.ticket, &VerificationContext { request_commitment })
            .await
            .map_err(|e| map_zk_error(req.request_id, e))?;

        if verified.token_class != req.token_class {
            return Err(EncryptedError::payment_required(
                req.request_id, "verified_class_mismatch", "authorization class mismatch",
            ));
        }

        // Durably reserve before dispatch. Pending state is an uncertain outcome,
        // not permission to retry after a TTL. It requires external reconciliation.
        let rkey = if verified.nullifier_key.is_empty() {
            replay_key(&req.ticket)
        } else {
            verified.nullifier_key
        };
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
                "ticket reserved or consumed; outcome may be unknown",
            ),
            ReserveError::Db => EncryptedError::internal(req.request_id, "db error"),
        })?;

        // Once reserved, no error path deletes the entry. Even a network error
        // may occur after the provider accepted the request.
        let provider_response = call_provider(&state, &req).await?;

        // Mark as spent.
        let spent_val = encode_nullifier_value(b's', now_ms_u64());
        mark_nullifier_spent(&state.nullifier_db, &rkey, &pending_val, &spent_val)
            .map_err(|_| EncryptedError::internal(req.request_id, "db error"))?;

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
                request_id: Some(env.request_id),
                code: e.code.to_string(),
                message: e.message.to_string(),
            },
        },
    };

    let payload_json = serde_json::to_vec(&payload)
        .map_err(|_| ApiError::internal(Some(env.request_id), "internal error".into()))?;

    finalize_encrypted_response(&state, &env, payload_json, started, Some(env.request_id)).await
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

    // Output duplication/provider metadata can exceed the class even after a
    // bounded upstream read. Return an encrypted categorical error; keep spend state.
    let payload_json = if payload_json.len() > req_env.token_class.envelope_response_plaintext_bytes() {
        serde_json::to_vec(&GatewayEnvelopePayload::Err {
            error: ErrorResponse {
                request_id: Some(req_env.request_id),
                code: "response_too_large".into(),
                message: "response exceeds token class; do not retry automatically".into(),
            },
        }).map_err(|_| ApiError::internal(request_id, "internal error".into()))?
    } else {
        payload_json
    };
    let resp_env = seal_response_at_gateway(&state.keypair, req_env, &payload_json)
        .map_err(|_| ApiError::internal(request_id, "internal error".into()))?;

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

    let mut builder = state.http.post(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .json(&body);
    if let Some(key) = &state.provider_api_key {
        builder = builder.bearer_auth(key);
    }

    let resp = builder.send().await.map_err(|_e| {
        EncryptedError::upstream(req.request_id, "upstream_network", "upstream network error")
    })?;

    if !resp.status().is_success() {
        // Redirects are not followed and provider error bodies are never reflected.
        warn!("upstream returned non-success status");
        return Err(EncryptedError::upstream(
            req.request_id, "upstream_error", "upstream error; dispatch outcome may be unknown",
        ));
    }
    let bytes = read_bounded_body(resp, req.token_class.envelope_response_plaintext_bytes())
        .await
        .map_err(|code| EncryptedError::upstream(req.request_id, code, "upstream response unavailable; do not retry automatically"))?;
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| {
        EncryptedError::upstream(req.request_id, "upstream_parse", "invalid upstream JSON")
    })?;

    Ok(ProviderChatCompletionResult {
        output: extract_provider_output(&body),
        body,
    })
}

fn approx_prompt_bytes(messages: &[zk_llm_common::types::ChatMessage]) -> usize {
    serde_json::to_vec(messages)
        .map(|bytes| bytes.len())
        .unwrap_or_else(|_| {
            messages
                .iter()
                .map(|m| m.role.len() + m.content.len())
                .sum()
        })
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

#[cfg(test)]
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
    _pending_ttl_ms: u64,
) -> std::result::Result<(), ReserveError> {
    // Any existing record, including legacy pending/unknown/malformed state,
    // refuses replay. Time passage alone cannot establish non-execution.
    let cas = db
        .compare_and_swap(rkey, None as Option<&[u8]>, Some(pending_val))
        .map_err(|_| ReserveError::Db)?;
    if cas.is_err() {
        return Err(ReserveError::AlreadyUsed);
    }
    db.flush().map_err(|_| ReserveError::Db)?;
    Ok(())
}

fn mark_nullifier_spent(
    db: &sled::Db,
    rkey: &[u8],
    pending_val: &[u8],
    spent_val: &[u8],
) -> std::result::Result<(), ReserveError> {
    let cas = db
        .compare_and_swap(rkey, Some(pending_val), Some(spent_val))
        .map_err(|_| ReserveError::Db)?;
    if cas.is_err() {
        return Err(ReserveError::Db);
    }
    db.flush().map_err(|_| ReserveError::Db)?;
    Ok(())
}

fn now_ms_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() * 1000) + (d.subsec_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_nullifier_value, encode_nullifier_value, is_dummy_bind_allowed,
        mark_nullifier_spent, reserve_nullifier, ReserveError,
    };
    use std::net::SocketAddr;

    fn temporary_db() -> sled::Db {
        sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db")
    }

    #[test]
    fn dummy_verifier_bind_policy_allows_loopback() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("socket addr");
        assert!(is_dummy_bind_allowed(addr, false));
    }

    #[test]
    fn dummy_verifier_bind_policy_rejects_non_loopback_by_default() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().expect("socket addr");
        assert!(!is_dummy_bind_allowed(addr, false));
    }

    #[test]
    fn dummy_verifier_bind_policy_allows_non_loopback_with_local_demo_override() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().expect("socket addr");
        assert!(is_dummy_bind_allowed(addr, true));
    }

    #[test]
    fn reserve_nullifier_rejects_existing_spent_value() {
        let db = temporary_db();
        let key = b"nullifier";
        let pending = encode_nullifier_value(b'p', 100);
        let spent = encode_nullifier_value(b's', 101);

        reserve_nullifier(&db, key, &pending, 1_000).expect("initial reserve");
        mark_nullifier_spent(&db, key, &pending, &spent).expect("mark spent");

        let err = reserve_nullifier(&db, key, &pending, 1_000).expect_err("spent rejects replay");
        assert!(matches!(err, ReserveError::AlreadyUsed));
    }

    #[test]
    fn reserve_nullifier_never_expires_ambiguous_pending() {
        let db = temporary_db();
        let key = b"nullifier";
        let stale = encode_nullifier_value(b'p', 1);
        let fresh = encode_nullifier_value(b'p', 10_000);
        db.insert(key, stale.clone()).expect("seed stale");
        db.flush().expect("flush seed");

        let error = reserve_nullifier(&db, key, &fresh, 10).expect_err("stale pending must refuse");
        assert!(matches!(error, ReserveError::AlreadyUsed));

        let stored = db.get(key).expect("read value").expect("value exists");
        assert_eq!(
            decode_nullifier_value(stored.as_ref()),
            decode_nullifier_value(&stale)
        );
    }
}
