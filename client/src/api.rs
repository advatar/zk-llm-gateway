use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{agent::AgentRuntime, manager::AgentManager};

/// Minimal local HTTP API around the personal-agent runtime.
///
/// This is intended for GUI integrations. It should be bound to localhost.
///
/// Security note:
/// - If you expose this beyond localhost, you MUST add authentication.
/// - This API can reveal private memory and full session history.
///
/// Multi-session note:
/// - When enabled (default), this API can manage multiple independent sessions keyed by `session_id`.
/// - Each session has its own local memory/history/redaction state to prevent cross-session leakage.
#[derive(Clone)]
pub struct ApiConfig {
    pub listen_addr: String,
    pub api_key: Option<String>,
    pub cors_allowed_origins: String,

    /// Default session id used by legacy endpoints (/v1/session, /v1/chat, etc).
    pub default_session_id: String,

    /// Enable multi-session endpoints under `/v1/sessions/...`.
    pub enable_multi_session: bool,

    /// SSE streaming: number of characters per chunk (simulated streaming).
    pub stream_chunk_chars: usize,
    /// SSE streaming: delay between chunks (ms).
    pub stream_chunk_delay_ms: u64,
}

#[derive(Clone)]
struct ApiState {
    manager: Arc<AgentManager>,
    api_key: Option<String>,
    default_session_id: String,
    stream_chunk_chars: usize,
    stream_chunk_delay_ms: u64,
}

pub async fn serve_http(config: ApiConfig, manager: Arc<AgentManager>) -> Result<()> {
    let state = ApiState {
        manager,
        api_key: config.api_key,
        default_session_id: config.default_session_id,
        stream_chunk_chars: config.stream_chunk_chars,
        stream_chunk_delay_ms: config.stream_chunk_delay_ms,
    };

    let mut app = Router::new()
        // health
        .route("/healthz", get(healthz))
        // Backward-compatible single-session endpoints (use default session id)
        .route("/v1/session", get(get_session_default))
        .route("/v1/messages", get(get_messages_default))
        .route("/v1/chat", post(post_chat_default))
        .route("/v1/chat/stream", post(post_chat_stream_default))
        .route(
            "/v1/memory",
            get(get_memory_default).post(post_memory_default),
        )
        .route("/v1/memory/search", post(post_memory_search_default))
        .route("/v1/redaction/term", post(post_redaction_term_default))
        .route("/v1/system", post(post_system_default))
        .route("/v1/save", post(post_save_default));

    if config.enable_multi_session {
        app = app
            // Session management
            .route("/v1/sessions", get(list_sessions).post(create_session))
            .route("/v1/sessions/:session_id", get(get_session_by_id))
            .route("/v1/sessions/:session_id/messages", get(get_messages_by_id))
            .route("/v1/sessions/:session_id/chat", post(post_chat_by_id))
            .route(
                "/v1/sessions/:session_id/chat/stream",
                post(post_chat_stream_by_id),
            )
            .route(
                "/v1/sessions/:session_id/memory",
                get(get_memory_by_id).post(post_memory_by_id),
            )
            .route(
                "/v1/sessions/:session_id/memory/search",
                post(post_memory_search_by_id),
            )
            .route(
                "/v1/sessions/:session_id/redaction/term",
                post(post_redaction_term_by_id),
            )
            .route("/v1/sessions/:session_id/system", post(post_system_by_id))
            .route("/v1/sessions/:session_id/save", post(post_save_by_id));
    }

    let app = app
        .layer(cors_layer(&config.cors_allowed_origins)?)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state));

    let addr: SocketAddr = config
        .listen_addr
        .parse()
        .context("invalid CLIENT_HTTP_LISTEN_ADDR")?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind http api")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http api server error")?;

    Ok(())
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

fn check_api_key(
    headers: &HeaderMap,
    expected: &Option<String>,
) -> std::result::Result<(), ApiError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let got = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if got != expected {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}

async fn get_agent(
    state: &ApiState,
    session_id: &str,
) -> std::result::Result<Arc<tokio::sync::Mutex<AgentRuntime>>, ApiError> {
    state
        .manager
        .get_or_load(session_id)
        .await
        .map_err(|e| ApiError::BadRequest(format!("{:#}", e)))
}

#[derive(Debug, Serialize)]
struct SessionView {
    session_id: String,
    system_prompt: String,
    summary: String,
    message_count: usize,
    memory_count: usize,
    token_class: String,
    model: String,
    session_path: String,
}

async fn get_session_view_for(
    state: &ApiState,
    session_id: &str,
) -> Result<Json<SessionView>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let agent = agent.lock().await;
    Ok(Json(SessionView {
        session_id: session_id.to_string(),
        system_prompt: agent.session.system_prompt.clone(),
        summary: agent.session.summary.clone(),
        message_count: agent.session.messages.len(),
        memory_count: agent.session.memory.len(),
        token_class: format!("{:?}", agent.token_class),
        model: agent.model.clone(),
        session_path: agent.session_path.display().to_string(),
    }))
}

async fn get_session_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<SessionView>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    get_session_view_for(&state, &state.default_session_id).await
}

async fn get_session_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionView>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    get_session_view_for(&state, &session_id).await
}

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    50
}

async fn get_messages_for(
    state: &ApiState,
    session_id: &str,
    limit: usize,
) -> Result<Json<Vec<zk_llm_common::types::ChatMessage>>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let agent = agent.lock().await;
    Ok(Json(agent.messages(limit)))
}

async fn get_messages_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Query(q): Query<MessagesQuery>,
) -> Result<Json<Vec<zk_llm_common::types::ChatMessage>>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    get_messages_for(&state, &state.default_session_id, q.limit).await
}

async fn get_messages_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Query(q): Query<MessagesQuery>,
) -> Result<Json<Vec<zk_llm_common::types::ChatMessage>>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    get_messages_for(&state, &session_id, q.limit).await
}

#[derive(Debug, Deserialize)]
struct ChatRequest {
    message: String,
}

#[derive(Debug, Serialize)]
struct ChatResponse {
    reply: String,
}

async fn post_chat_for(
    state: &ApiState,
    session_id: &str,
    message: String,
) -> Result<Json<ChatResponse>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let mut agent = agent.lock().await;
    let reply = agent
        .send_user_message(message)
        .await
        .map_err(ApiError::from_anyhow)?;
    Ok(Json(ChatResponse { reply }))
}

async fn post_chat_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<ChatRequest>,
) -> Result<Json<ChatResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_chat_for(&state, &state.default_session_id, req.message).await
}

async fn post_chat_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Json(req): Json<ChatRequest>,
) -> Result<Json<ChatResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_chat_for(&state, &session_id, req.message).await
}

#[derive(Debug, Serialize)]
struct StreamStart {
    request_id: String,
    session_id: String,
}

#[derive(Debug, Serialize)]
struct StreamDelta {
    text: String,
}

#[derive(Debug, Serialize)]
struct StreamDone {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct StreamError {
    error: String,
}

/// Streaming chat endpoint (SSE).
///
/// This is "simulated streaming": the gateway returns a full response envelope,
/// then the client emits it to the GUI in fixed-size chunks at a constant cadence.
///
/// This is useful for GUIs and lets you keep the privacy-preserving envelope format
/// unchanged while still providing a streaming UX locally.
async fn post_chat_stream_for(
    state: Arc<ApiState>,
    session_id: String,
    req: ChatRequest,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = check_api_key(&headers, &state.api_key) {
        return e.into_response();
    }

    let agent = match state.manager.get_or_load(&session_id).await {
        Ok(a) => a,
        Err(e) => return ApiError::BadRequest(format!("{:#}", e)).into_response(),
    };

    let (tx, rx) = mpsc::channel::<Event>(64);

    let request_id = Uuid::new_v4().to_string();
    let chunk_chars = state.stream_chunk_chars.max(1);
    let delay = Duration::from_millis(state.stream_chunk_delay_ms);

    tokio::spawn(async move {
        let start = StreamStart {
            request_id: request_id.clone(),
            session_id: session_id.clone(),
        };
        let _ = tx
            .send(
                Event::default()
                    .event("start")
                    .data(serde_json::to_string(&start).unwrap()),
            )
            .await;

        // Acquire the agent lock for the duration of the call.
        let mut a = agent.lock().await;
        match a.send_user_message(req.message).await {
            Ok(full) => {
                for chunk in chunk_string(&full, chunk_chars) {
                    let d = StreamDelta { text: chunk };
                    let _ = tx
                        .send(
                            Event::default()
                                .event("delta")
                                .data(serde_json::to_string(&d).unwrap()),
                        )
                        .await;
                    tokio::time::sleep(delay).await;
                }
                let done = StreamDone { ok: true };
                let _ = tx
                    .send(
                        Event::default()
                            .event("done")
                            .data(serde_json::to_string(&done).unwrap()),
                    )
                    .await;
            }
            Err(e) => {
                let err = StreamError {
                    error: format!("{:#}", e),
                };
                let _ = tx
                    .send(
                        Event::default()
                            .event("error")
                            .data(serde_json::to_string(&err).unwrap()),
                    )
                    .await;
            }
        }
    });

    let stream = futures::stream::unfold(rx, |mut rx| async {
        match rx.recv().await {
            Some(ev) => Some((Ok::<Event, Infallible>(ev), rx)),
            None => None,
        }
    });

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

async fn post_chat_stream_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<ChatRequest>,
) -> Response {
    post_chat_stream_for(
        state.clone(),
        state.default_session_id.clone(),
        req,
        headers,
    )
    .await
}

async fn post_chat_stream_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Json(req): Json<ChatRequest>,
) -> Response {
    post_chat_stream_for(state.clone(), session_id, req, headers).await
}

async fn get_memory_for(
    state: &ApiState,
    session_id: &str,
) -> Result<Json<Vec<crate::session::MemoryItem>>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let agent = agent.lock().await;
    Ok(Json(agent.list_memory()))
}

async fn get_memory_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Vec<crate::session::MemoryItem>>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    get_memory_for(&state, &state.default_session_id).await
}

async fn get_memory_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<crate::session::MemoryItem>>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    get_memory_for(&state, &session_id).await
}

#[derive(Debug, Deserialize)]
struct MemoryAddRequest {
    text: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OkResponse {
    ok: bool,
}

async fn post_memory_for(
    state: &ApiState,
    session_id: &str,
    req: MemoryAddRequest,
) -> Result<Json<OkResponse>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let mut agent = agent.lock().await;
    agent.remember(req.text, req.tags);
    Ok(Json(OkResponse { ok: true }))
}

async fn post_memory_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<MemoryAddRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_memory_for(&state, &state.default_session_id, req).await
}

async fn post_memory_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Json(req): Json<MemoryAddRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_memory_for(&state, &session_id, req).await
}

#[derive(Debug, Deserialize)]
struct MemorySearchRequest {
    query: String,
    #[serde(default = "default_k")]
    k: usize,
}

fn default_k() -> usize {
    8
}

#[derive(Debug, Serialize)]
struct MemorySearchResponse {
    memories: Vec<crate::memory_store::Doc>,
    recall: Vec<zk_llm_common::types::ChatMessage>,
}

async fn post_memory_search_for(
    state: &ApiState,
    session_id: &str,
    req: MemorySearchRequest,
) -> Result<Json<MemorySearchResponse>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let agent = agent.lock().await;
    let exclude_cutoff = agent
        .session
        .messages
        .len()
        .saturating_sub(agent.prompt_cfg.max_recent_messages);
    let ctx = agent
        .memory_store
        .retrieve_context(&req.query, req.k, req.k, Some(exclude_cutoff));
    Ok(Json(MemorySearchResponse {
        memories: ctx.memories,
        recall: ctx.recall,
    }))
}

async fn post_memory_search_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<MemorySearchRequest>,
) -> Result<Json<MemorySearchResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_memory_search_for(&state, &state.default_session_id, req).await
}

async fn post_memory_search_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Json(req): Json<MemorySearchRequest>,
) -> Result<Json<MemorySearchResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_memory_search_for(&state, &session_id, req).await
}

#[derive(Debug, Deserialize)]
struct RedactionTermRequest {
    term: String,
}

async fn post_redaction_term_for(
    state: &ApiState,
    session_id: &str,
    term: String,
) -> Result<Json<OkResponse>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let mut agent = agent.lock().await;
    agent.add_redaction_term(term);
    Ok(Json(OkResponse { ok: true }))
}

async fn post_redaction_term_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<RedactionTermRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_redaction_term_for(&state, &state.default_session_id, req.term).await
}

async fn post_redaction_term_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Json(req): Json<RedactionTermRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_redaction_term_for(&state, &session_id, req.term).await
}

#[derive(Debug, Deserialize)]
struct SystemRequest {
    system: String,
}

async fn post_system_for(
    state: &ApiState,
    session_id: &str,
    system: String,
) -> Result<Json<OkResponse>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let mut agent = agent.lock().await;
    agent.set_system_prompt(system);
    Ok(Json(OkResponse { ok: true }))
}

async fn post_system_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<SystemRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_system_for(&state, &state.default_session_id, req.system).await
}

async fn post_system_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
    Json(req): Json<SystemRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_system_for(&state, &session_id, req.system).await
}

async fn post_save_for(state: &ApiState, session_id: &str) -> Result<Json<OkResponse>, ApiError> {
    let agent = get_agent(state, session_id).await?;
    let agent = agent.lock().await;
    agent.persist();
    Ok(Json(OkResponse { ok: true }))
}

async fn post_save_default(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_save_for(&state, &state.default_session_id).await
}

async fn post_save_by_id(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
) -> Result<Json<OkResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    post_save_for(&state, &session_id).await
}

#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    system: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateSessionResponse {
    session_id: String,
}

async fn create_session(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    let id = state
        .manager
        .create_session(req.session_id, req.system)
        .await
        .map_err(ApiError::from_anyhow)?;
    Ok(Json(CreateSessionResponse { session_id: id }))
}

async fn list_sessions(
    headers: HeaderMap,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Vec<crate::manager::SessionInfo>>, ApiError> {
    check_api_key(&headers, &state.api_key)?;
    let s = state
        .manager
        .list_sessions()
        .await
        .map_err(ApiError::from_anyhow)?;
    Ok(Json(s))
}

fn chunk_string(s: &str, chunk_chars: usize) -> Vec<String> {
    if s.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut buf = String::new();
    for ch in s.chars() {
        buf.push(ch);
        if buf.chars().count() >= chunk_chars {
            out.push(buf);
            buf = String::new();
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    BadRequest(String),
    Internal(String),
}

impl ApiError {
    fn unauthorized() -> Self {
        ApiError::Unauthorized
    }

    fn from_anyhow(e: anyhow::Error) -> Self {
        // Coarsen details slightly for safety, but keep dev-friendly errors.
        ApiError::Internal(format!("{:#}", e))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
            ApiError::Internal(s) => (StatusCode::INTERNAL_SERVER_ERROR, s),
        };

        let body = serde_json::json!({"error": msg});
        (status, Json(body)).into_response()
    }
}
