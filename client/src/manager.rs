use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result};
use log::warn;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use zk_llm_common::token::TokenClass;

use crate::{
    agent::AgentRuntime,
    local_ai::LocalAiClient,
    prompt::PromptBuildConfig,
    redaction::{RedactMode, Redactor},
    session::{load_session, save_session, Session},
    tickets::TicketSource,
};

/// Configuration shared by all sessions managed by an `AgentManager`.
#[derive(Clone)]
pub struct AgentManagerConfig {
    pub endpoint_url: String,
    pub gateway_public_bytes: [u8; 32],
    pub model: String,
    pub token_class: TokenClass,
    pub redact_mode: RedactMode,
    pub extra_terms: Vec<String>,
    pub prompt_cfg: PromptBuildConfig,
    pub session_key: Option<[u8; 32]>,
    pub sessions_dir: PathBuf,

    /// Default system prompt used when creating a new session without an explicit system prompt.
    pub default_system_prompt: String,

    /// If set, the manager will use this path for the default session id (useful for backward compat).
    pub default_session_id: String,
    pub default_session_path_override: Option<PathBuf>,

    /// Shared ticket source across sessions to avoid ticket reuse.
    pub ticket_source: Arc<dyn TicketSource>,

    /// Optional local summarizer (should be localhost).
    pub local_ai: Option<LocalAiClient>,

    /// HTTP timeout (ms) for gateway calls.
    pub timeout_ms: u64,

    /// Whether to index messages for retrieval.
    pub index_messages: bool,
    pub max_messages_indexed: usize,
}

/// Information about a session for listing.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub path: String,
    pub exists_on_disk: bool,
}

/// Manages multiple `AgentRuntime` instances keyed by `session_id`.
///
/// Primary goals:
/// - support multi-session GUIs (multiple tabs/users)
/// - avoid cross-session leakage (memory, redaction state, chat history)
/// - share a ticket source (avoid nullifier reuse / ticket reuse)
pub struct AgentManager {
    cfg: AgentManagerConfig,
    // Loaded sessions (in memory)
    sessions: RwLock<HashMap<String, Arc<Mutex<AgentRuntime>>>>,
}

impl AgentManager {
    pub fn new(cfg: AgentManagerConfig) -> Result<Self> {
        if !cfg.sessions_dir.exists() {
            fs::create_dir_all(&cfg.sessions_dir)
                .with_context(|| format!("create sessions dir {}", cfg.sessions_dir.display()))?;
        }
        Ok(Self {
            cfg,
            sessions: RwLock::new(HashMap::new()),
        })
    }

    fn validate_session_id(session_id: &str) -> Result<()> {
        if session_id.is_empty() || session_id.len() > 64 {
            anyhow::bail!("invalid session_id length");
        }
        // Allow only a conservative set to avoid path traversal.
        if !session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!("invalid session_id characters (allowed: [A-Za-z0-9_-])");
        }
        Ok(())
    }

    fn session_path_for(&self, session_id: &str) -> PathBuf {
        if session_id == self.cfg.default_session_id {
            if let Some(p) = &self.cfg.default_session_path_override {
                return p.clone();
            }
        }
        self.cfg
            .sessions_dir
            .join(format!("{}.session.json", session_id))
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        // Disk scan
        let mut out = Vec::new();
        let entries = fs::read_dir(&self.cfg.sessions_dir)
            .with_context(|| format!("read sessions dir {}", self.cfg.sessions_dir.display()))?;

        for e in entries {
            let e = e?;
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = match p.file_name().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if !name.ends_with(".session.json") {
                continue;
            }
            let id = name.trim_end_matches(".session.json").to_string();
            if Self::validate_session_id(&id).is_err() {
                continue;
            }
            out.push(SessionInfo {
                session_id: id,
                path: p.display().to_string(),
                exists_on_disk: true,
            });
        }

        // Ensure default session is visible even if overridden path doesn't follow pattern
        if let Some(p) = &self.cfg.default_session_path_override {
            let id = self.cfg.default_session_id.clone();
            if !out.iter().any(|s| s.session_id == id) {
                out.push(SessionInfo {
                    session_id: id,
                    path: p.display().to_string(),
                    exists_on_disk: p.exists(),
                });
            }
        }

        // Merge in-memory sessions that might not be on disk yet (rare).
        let guard = self.sessions.read().await;
        for (id, _agent) in guard.iter() {
            if !out.iter().any(|s| s.session_id == *id) {
                out.push(SessionInfo {
                    session_id: id.clone(),
                    path: self.session_path_for(id).display().to_string(),
                    exists_on_disk: self.session_path_for(id).exists(),
                });
            }
        }

        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        Ok(out)
    }

    pub async fn create_session(
        &self,
        session_id: Option<String>,
        system_prompt: Option<String>,
    ) -> Result<String> {
        let id = session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        Self::validate_session_id(&id)?;

        let path = self.session_path_for(&id);
        if path.exists() {
            anyhow::bail!("session already exists");
        }

        let system = system_prompt.unwrap_or_else(|| self.cfg.default_system_prompt.clone());
        let session = Session::new(system);
        save_session(&path, &session, self.cfg.session_key).context("save new session")?;

        // Load into memory
        let _ = self.get_or_load(&id).await?;
        Ok(id)
    }

    pub async fn get_or_load(&self, session_id: &str) -> Result<Arc<Mutex<AgentRuntime>>> {
        Self::validate_session_id(session_id)?;
        // Fast path: already loaded
        {
            let guard = self.sessions.read().await;
            if let Some(a) = guard.get(session_id) {
                return Ok(a.clone());
            }
        }

        // Slow path: load or create and insert (double-checked)
        let mut guard = self.sessions.write().await;
        if let Some(a) = guard.get(session_id) {
            return Ok(a.clone());
        }

        let path = self.session_path_for(session_id);
        let (session, created) = if path.exists() {
            (
                load_session(&path, self.cfg.session_key).context("load session")?,
                false,
            )
        } else {
            // Create with default prompt
            let s = Session::new(self.cfg.default_system_prompt.clone());
            save_session(&path, &s, self.cfg.session_key).ok();
            (s, true)
        };

        if created {
            warn!(
                "created new session_id={} at {}",
                session_id,
                path.display()
            );
        }

        let agent = self.build_agent(path, session)?;
        let agent = Arc::new(Mutex::new(agent));
        guard.insert(session_id.to_string(), agent.clone());
        Ok(agent)
    }

    /// Insert a pre-built agent under a session id.
    ///
    /// This is primarily used for backward-compatible single-session CLI flows,
    /// where the session file path is explicitly configured.
    pub async fn insert_prebuilt(&self, session_id: String, agent: AgentRuntime) -> Result<()> {
        Self::validate_session_id(&session_id)?;
        let mut guard = self.sessions.write().await;
        guard.insert(session_id, Arc::new(Mutex::new(agent)));
        Ok(())
    }

    fn build_agent(&self, session_path: PathBuf, mut session: Session) -> Result<AgentRuntime> {
        // Load redactor from session state.
        let mut redactor =
            Redactor::from_state(session.redaction.clone()).context("init redactor")?;

        // Merge session custom terms + global extra terms.
        for t in session.redaction.custom_terms.clone() {
            redactor.add_custom_term(t);
        }
        for t in &self.cfg.extra_terms {
            redactor.add_custom_term(t.clone());
        }

        // Persist redaction state (in case we merged terms)
        session.redaction = redactor.state().clone();
        save_session(&session_path, &session, self.cfg.session_key).ok();

        AgentRuntime::new(
            self.cfg.endpoint_url.clone(),
            self.cfg.gateway_public_bytes,
            self.cfg.model.clone(),
            self.cfg.token_class,
            self.cfg.redact_mode,
            self.cfg.extra_terms.clone(),
            self.cfg.prompt_cfg.clone(),
            session_path,
            self.cfg.session_key,
            session,
            redactor,
            self.cfg.ticket_source.clone(),
            self.cfg.local_ai.clone(),
            self.cfg.timeout_ms,
            self.cfg.index_messages,
            self.cfg.max_messages_indexed,
        )
    }
}
