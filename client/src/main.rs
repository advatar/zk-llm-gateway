mod agent;
mod api;
mod local_ai;
mod manager;
mod memory_store;
mod prompt;
mod redaction;
mod session;
mod tickets;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, ValueEnum};
use log::warn;

use zk_llm_common::token::TokenClass;

use crate::{
    agent::AgentRuntime,
    api::{serve_http, ApiConfig},
    local_ai::{LocalAiClient, LocalAiConfig},
    manager::{AgentManager, AgentManagerConfig},
    prompt::PromptBuildConfig,
    redaction::{RedactMode, Redactor},
    session::{load_session, save_session, Session},
    tickets::{FileTicketSource, TicketSource},
};

#[derive(Parser, Debug)]
#[command(name = "zk-llm-client")]
struct Cli {
    /// Relay endpoint (recommended) or direct gateway /v1/infer endpoint.
    ///
    /// Examples:
    /// - Relay:   http://127.0.0.1:8081/relay
    /// - Gateway: http://127.0.0.1:8080/v1/infer
    #[arg(
        long,
        env = "CLIENT_ENDPOINT_URL",
        default_value = "http://127.0.0.1:8081/relay"
    )]
    endpoint_url: String,

    /// Base64-encoded 32-byte gateway public key.
    #[arg(long, env = "GATEWAY_PUBLIC_KEY_B64")]
    gateway_public_key_b64: String,

    /// Model name (OpenAI-compatible).
    #[arg(long, env = "CLIENT_MODEL", default_value = "gpt-4o-mini")]
    model: String,

    /// Token class (privacy/billing bucket).
    #[arg(long, value_enum, env = "CLIENT_TOKEN_CLASS", default_value = "c2048")]
    token_class: TokenClassArg,

    /// System prompt for a NEW session. If session exists, this is ignored unless --reset-system is set.
    #[arg(long)]
    system: Option<String>,

    /// Reset the stored system prompt in an existing session.
    #[arg(long, default_value_t = false)]
    reset_system: bool,

    /// User prompt for one-shot mode.
    #[arg(long)]
    user: Option<String>,

    /// Interactive REPL mode for long chat sessions.
    #[arg(long, default_value_t = false)]
    repl: bool,

    /// Start a local HTTP API server for GUI integration (bind to localhost).
    ///
    /// Example: 127.0.0.1:8090
    #[arg(long, env = "CLIENT_HTTP_LISTEN_ADDR")]
    http_listen_addr: Option<String>,

    /// Optional API key required via header `x-api-key` for the local HTTP API.
    #[arg(long, env = "CLIENT_HTTP_API_KEY")]
    http_api_key: Option<String>,

    /// Comma-separated browser origins allowed to call the local HTTP API.
    #[arg(
        long,
        env = "CLIENT_HTTP_CORS_ALLOWED_ORIGINS",
        default_value = "http://localhost:3000,http://127.0.0.1:3000"
    )]
    http_cors_allowed_origins: String,

    /// Enable multi-session mode for the local HTTP API (multiple sessions keyed by session_id).
    #[arg(long, env = "CLIENT_MULTI_SESSION", default_value_t = true, action = clap::ArgAction::Set)]
    multi_session: bool,

    /// Directory to store sessions in multi-session mode.
    #[arg(long, env = "CLIENT_SESSIONS_DIR", default_value = "./sessions")]
    sessions_dir: PathBuf,

    /// Default session id used by legacy endpoints (/v1/session, /v1/chat, etc).
    #[arg(long, env = "CLIENT_DEFAULT_SESSION_ID", default_value = "default")]
    default_session_id: String,

    /// SSE streaming: number of characters per chunk.
    #[arg(long, env = "CLIENT_STREAM_CHUNK_CHARS", default_value_t = 32)]
    stream_chunk_chars: usize,

    /// SSE streaming: delay between chunks (ms).
    #[arg(long, env = "CLIENT_STREAM_CHUNK_DELAY_MS", default_value_t = 15)]
    stream_chunk_delay_ms: u64,

    /// Local session file. Strongly recommended for personal-agent use.
    #[arg(long, default_value = "./sessions/default.session.json")]
    session_file: PathBuf,

    /// Optional base64-encoded 32-byte key to encrypt the session file at rest.
    #[arg(long, env = "SESSION_KEY_B64")]
    session_key_b64: Option<String>,

    /// Keep only the last N messages when sending to the remote model.
    #[arg(long, default_value_t = 8)]
    max_recent_messages: usize,

    /// Max number of memory items to include.
    #[arg(long, default_value_t = 8)]
    max_memory_items: usize,

    /// Max number of "recall" snippets (older messages) to include.
    #[arg(long, default_value_t = 6)]
    max_recall_snippets: usize,

    /// Whether to include the rolling local summary in remote requests.
    #[arg(long, default_value_t = true)]
    include_summary: bool,

    /// Optional: pad the system prompt toward the token-class size limit.
    /// This reduces provider-visible prompt-length metadata at the cost of more tokens.
    #[arg(long, env = "CLIENT_PAD_SYSTEM_PROMPT", default_value_t = true, action = clap::ArgAction::Set)]
    pad_system_prompt: bool,

    /// Upper bound on how many bytes of system-padding to add.
    #[arg(long, env = "CLIENT_MAX_PADDING_BYTES", default_value_t = 65536)]
    max_padding_bytes: usize,

    /// Index chat messages for retrieval (RAG recall). Recommended for long sessions.
    #[arg(long, env = "CLIENT_INDEX_MESSAGES", default_value_t = true)]
    index_messages: bool,

    /// Maximum number of messages to index (most recent). Prevents runaway RAM.
    #[arg(long, env = "CLIENT_MAX_MESSAGES_INDEXED", default_value_t = 5000)]
    max_messages_indexed: usize,

    /// Redaction mode.
    #[arg(long, value_enum, default_value = "basic")]
    redact_mode: RedactMode,

    /// Add an explicit term to redact (repeatable).
    #[arg(long)]
    sensitive_term: Vec<String>,

    /// Load additional sensitive terms (one per line).
    #[arg(long)]
    sensitive_terms_file: Option<PathBuf>,

    /// Optional local summarizer base URL (OpenAI-compatible). Should be local-only.
    #[arg(long, env = "LOCAL_SUMMARIZER_URL")]
    local_summarizer_url: Option<String>,

    /// Local summarizer model.
    #[arg(long, env = "LOCAL_SUMMARIZER_MODEL", default_value = "llama-3.1-8b")]
    local_summarizer_model: String,

    /// Local summarizer API key (usually none for localhost).
    #[arg(long, env = "LOCAL_SUMMARIZER_API_KEY")]
    local_summarizer_api_key: Option<String>,

    /// Optional ticket file (JSON array of ZkTicket). Required unless dummy tickets are explicitly enabled.
    #[arg(long)]
    ticket_file: Option<PathBuf>,

    /// Use development-only dummy tickets when no ticket file is provided.
    #[arg(long, env = "CLIENT_USE_DUMMY_TICKETS", default_value_t = false)]
    use_dummy_tickets: bool,

    /// Timeout (ms) for each HTTP request.
    #[arg(long, env = "CLIENT_TIMEOUT_MS", default_value_t = 120_000)]
    timeout_ms: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum TokenClassArg {
    C256,
    C512,
    C1024,
    C2048,
    C4096,
}

impl From<TokenClassArg> for TokenClass {
    fn from(v: TokenClassArg) -> Self {
        match v {
            TokenClassArg::C256 => TokenClass::C256,
            TokenClassArg::C512 => TokenClass::C512,
            TokenClassArg::C1024 => TokenClass::C1024,
            TokenClassArg::C2048 => TokenClass::C2048,
            TokenClassArg::C4096 => TokenClass::C4096,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    if cli.http_listen_addr.is_none() && !cli.repl && cli.user.is_none() {
        anyhow::bail!("Provide --user, --repl, or --http-listen-addr");
    }
    validate_ticket_source_config(&cli)?;

    let gateway_public_bytes =
        parse_b64_32(&cli.gateway_public_key_b64).context("invalid GATEWAY_PUBLIC_KEY_B64")?;

    let session_key = match cli.session_key_b64.as_deref() {
        Some(s) => Some(parse_b64_32(s).context("invalid SESSION_KEY_B64")?),
        None => None,
    };

    // Load session or create a new one.
    let mut session = if cli.session_file.exists() {
        load_session(&cli.session_file, session_key).context("load session")?
    } else {
        let system = cli
            .system
            .clone()
            .unwrap_or_else(|| "You are a helpful assistant.".to_string());
        let s = Session::new(system);
        save_session(&cli.session_file, &s, session_key).ok();
        s
    };

    if cli.reset_system {
        if let Some(sys) = &cli.system {
            session.system_prompt = sys.clone();
        } else {
            warn!("--reset-system provided but --system is missing; ignoring");
        }
    }

    // Load redactor from session state.
    let redactor = Redactor::from_state(session.redaction.clone()).context("init redactor")?;

    // Load extra sensitive terms.
    let mut extra_terms = cli.sensitive_term.clone();
    if let Some(path) = &cli.sensitive_terms_file {
        extra_terms.extend(load_terms_file(path).unwrap_or_default());
    }

    // Optional local summarizer
    let local_ai = if let Some(url) = &cli.local_summarizer_url {
        Some(LocalAiClient::new(LocalAiConfig {
            base_url: url.clone(),
            model: cli.local_summarizer_model.clone(),
            api_key: cli.local_summarizer_api_key.clone(),
            timeout_ms: cli.timeout_ms,
        })?)
    } else {
        None
    };

    // Ticket source (shared across sessions to avoid ticket reuse)
    let ticket_source = build_ticket_source(&cli)?;

    let token_class: TokenClass = cli.token_class.into();

    let prompt_cfg = PromptBuildConfig {
        max_recent_messages: cli.max_recent_messages,
        max_memory_items: cli.max_memory_items,
        include_summary: cli.include_summary,
        normalize_context_blocks: true,
        pad_system_prompt: cli.pad_system_prompt,
        max_padding_bytes: cli.max_padding_bytes,
        max_recall_snippets: cli.max_recall_snippets,
    };

    let mut agent = AgentRuntime::new(
        cli.endpoint_url.clone(),
        gateway_public_bytes,
        cli.model.clone(),
        token_class,
        cli.redact_mode,
        extra_terms.clone(),
        prompt_cfg.clone(),
        cli.session_file.clone(),
        session_key,
        session,
        redactor,
        ticket_source.clone(),
        local_ai.clone(),
        cli.timeout_ms,
        cli.index_messages,
        cli.max_messages_indexed,
    )?;

    if let Some(listen) = &cli.http_listen_addr {
        if !listen.starts_with("127.0.0.1") && !listen.starts_with("localhost") {
            warn!(
                "HTTP API is listening on '{}' (not localhost). This can expose your private memory/session. Set CLIENT_HTTP_API_KEY.",
                listen
            );
        }
        if cli.http_api_key.is_none() {
            warn!("No CLIENT_HTTP_API_KEY set; local HTTP API is unauthenticated.");
        }

        // Build a multi-session manager. Even in "single-session" CLI usage, this keeps the HTTP API
        // surface consistent and enables GUIs to manage multiple sessions safely.
        let manager = AgentManager::new(AgentManagerConfig {
            endpoint_url: cli.endpoint_url.clone(),
            gateway_public_bytes: gateway_public_bytes,
            model: cli.model.clone(),
            token_class: token_class,
            redact_mode: cli.redact_mode,
            extra_terms: extra_terms.clone(),
            prompt_cfg: prompt_cfg.clone(),
            session_key: session_key,
            sessions_dir: cli.sessions_dir.clone(),
            default_system_prompt: cli
                .system
                .clone()
                .unwrap_or_else(|| "You are a helpful assistant.".to_string()),
            default_session_id: cli.default_session_id.clone(),
            default_session_path_override: Some(cli.session_file.clone()),
            ticket_source: ticket_source.clone(),
            local_ai: local_ai.clone(),
            timeout_ms: cli.timeout_ms,
            index_messages: cli.index_messages,
            max_messages_indexed: cli.max_messages_indexed,
        })?;

        // Insert the pre-built default session agent (from --session-file).
        manager
            .insert_prebuilt(cli.default_session_id.clone(), agent)
            .await?;

        let manager = std::sync::Arc::new(manager);

        serve_http(
            ApiConfig {
                listen_addr: listen.clone(),
                api_key: cli.http_api_key.clone(),
                cors_allowed_origins: cli.http_cors_allowed_origins.clone(),
                default_session_id: cli.default_session_id.clone(),
                enable_multi_session: cli.multi_session,
                stream_chunk_chars: cli.stream_chunk_chars,
                stream_chunk_delay_ms: cli.stream_chunk_delay_ms,
            },
            manager,
        )
        .await?;
        return Ok(());
    }

    if cli.repl {
        agent.repl().await?;
        return Ok(());
    }

    if let Some(user_msg) = cli.user {
        let out = agent.send_user_message(user_msg).await?;
        println!("{}", out);
    }

    Ok(())
}

fn load_terms_file(path: &PathBuf) -> Result<Vec<String>> {
    let bytes =
        fs::read(path).with_context(|| format!("read sensitive terms file {}", path.display()))?;
    let s = String::from_utf8_lossy(&bytes);
    Ok(s.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

fn validate_ticket_source_config(cli: &Cli) -> Result<()> {
    if cli.ticket_file.is_some() || cli.use_dummy_tickets {
        return Ok(());
    }

    anyhow::bail!(
        "ticket source is required: pass --ticket-file <path> for issued tickets, \
         or set --use-dummy-tickets / CLIENT_USE_DUMMY_TICKETS=true for local development"
    )
}

fn build_ticket_source(cli: &Cli) -> Result<std::sync::Arc<dyn TicketSource>> {
    if let Some(path) = &cli.ticket_file {
        return Ok(std::sync::Arc::new(FileTicketSource::load(path.clone())?));
    }

    if cli.use_dummy_tickets {
        warn!("using development-only dummy tickets; configure --ticket-file for production usage");
        return Ok(std::sync::Arc::new(tickets::DummyTicketSource::default()));
    }

    validate_ticket_source_config(cli)?;
    unreachable!("ticket source validation should reject missing sources")
}

fn parse_b64_32(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s).context("invalid base64")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    const PUBLIC_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn parse_cli(extra: &[&str]) -> Cli {
        let mut args = vec![
            "zk_llm_client",
            "--gateway-public-key-b64",
            PUBLIC_KEY_B64,
            "--endpoint-url",
            "http://127.0.0.1:8081/relay",
            "--user",
            "hello",
        ];
        args.extend_from_slice(extra);
        Cli::parse_from(args)
    }

    #[test]
    fn ticket_source_requires_file_or_explicit_dummy_opt_in() {
        let cli = parse_cli(&[]);

        let err = validate_ticket_source_config(&cli).unwrap_err();
        assert!(err.to_string().contains("--ticket-file"));
        assert!(err.to_string().contains("--use-dummy-tickets"));
    }

    #[test]
    fn ticket_source_accepts_explicit_dummy_opt_in() {
        let cli = parse_cli(&["--use-dummy-tickets"]);

        validate_ticket_source_config(&cli).expect("dummy tickets are explicitly allowed");
    }

    #[test]
    fn ticket_source_accepts_file_source() {
        let cli = parse_cli(&["--ticket-file", "./tickets.json"]);

        validate_ticket_source_config(&cli).expect("ticket file source is allowed");
    }
}
