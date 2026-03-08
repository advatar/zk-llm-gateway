use std::{
    io::{self, Write},
    time::Duration,
};

use anyhow::{Context, Result};
use log::{info, warn};
use uuid::Uuid;

use zk_llm_common::{
    envelope::seal_request_for_gateway,
    token::TokenClass,
    types::{ChatMessage, GatewayEnvelopePayload, InferenceRequest},
};

use crate::{
    local_ai::LocalAiClient,
    memory_store::{MemoryStore, RetrievedContext},
    prompt::{build_remote_messages_with_retrieval, PromptBuildConfig},
    redaction::{RedactMode, Redactor},
    session::{save_session, Session},
    tickets::TicketSource,
};

/// The local "personal agent" runtime.
///
/// This object owns:
/// - the local session (full history + private memory)
/// - a redactor (so we can send placeholders remotely but show originals locally)
/// - a local retrieval index (RAG-style recall)
/// - HTTP client wiring to the encrypted gateway
///
/// It is designed to be used from:
/// - interactive REPL
/// - a local HTTP API for GUI integration
pub struct AgentRuntime {
    pub endpoint_url: String,
    pub gateway_public_bytes: [u8; 32],
    pub model: String,
    pub token_class: TokenClass,
    pub redact_mode: RedactMode,
    pub extra_terms: Vec<String>,
    pub prompt_cfg: PromptBuildConfig,
    pub session_path: std::path::PathBuf,
    pub session_key: Option<[u8; 32]>,

    pub session: Session,
    pub redactor: Redactor,
    pub memory_store: MemoryStore,

    pub ticket_source: std::sync::Arc<dyn TicketSource>,
    pub local_ai: Option<LocalAiClient>,
    pub http: reqwest::Client,
}

impl AgentRuntime {
    pub fn new(
        endpoint_url: String,
        gateway_public_bytes: [u8; 32],
        model: String,
        token_class: TokenClass,
        redact_mode: RedactMode,
        extra_terms: Vec<String>,
        prompt_cfg: PromptBuildConfig,
        session_path: std::path::PathBuf,
        session_key: Option<[u8; 32]>,
        mut session: Session,
        mut redactor: Redactor,
        ticket_source: std::sync::Arc<dyn TicketSource>,
        local_ai: Option<LocalAiClient>,
        timeout_ms: u64,
        index_messages: bool,
        max_messages_indexed: usize,
    ) -> Result<Self> {
        // Merge session-stored custom terms into the active redactor.
        for t in session.redaction.custom_terms.clone() {
            redactor.add_custom_term(t);
        }
        for t in &extra_terms {
            redactor.add_custom_term(t.clone());
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("build http client")?;

        // Build RAG index from existing session.
        let mut memory_store = MemoryStore::new();
        memory_store.rebuild_from_session(
            &session.memory,
            &session.messages,
            index_messages,
            max_messages_indexed,
        );

        // Persist redaction state (in case we merged terms).
        session.redaction = redactor.state().clone();
        save_session(&session_path, &session, session_key).ok();

        Ok(Self {
            endpoint_url,
            gateway_public_bytes,
            model,
            token_class,
            redact_mode,
            extra_terms,
            prompt_cfg,
            session_path,
            session_key,
            session,
            redactor,
            memory_store,
            ticket_source,
            local_ai,
            http,
        })
    }

    /// Add a memory item locally and index it.
    pub fn remember(&mut self, text: String, tags: Vec<String>) {
        self.session.push_memory(text, tags);
        if let Some(item) = self.session.memory.last() {
            self.memory_store.add_memory_item(item);
        }
        self.persist();
    }

    pub fn list_memory(&self) -> Vec<crate::session::MemoryItem> {
        self.session.memory.clone()
    }

    pub fn add_redaction_term(&mut self, term: String) {
        self.redactor.add_custom_term(term);
        self.session.redaction = self.redactor.state().clone();
        self.persist();
    }

    pub fn set_system_prompt(&mut self, system: String) {
        self.session.system_prompt = system;
        self.persist();
    }

    pub fn messages(&self, limit: usize) -> Vec<ChatMessage> {
        let n = limit.min(self.session.messages.len());
        self.session.messages[self.session.messages.len().saturating_sub(n)..].to_vec()
    }

    pub fn persist(&self) {
        let _ = save_session(&self.session_path, &self.session, self.session_key);
    }

    /// Core: send a user message through the privacy-preserving gateway.
    pub async fn send_user_message(&mut self, user_msg: String) -> Result<String> {
        // Store raw user message locally.
        let user_index = self.session.messages.len();
        self.session.messages.push(ChatMessage {
            role: "user".to_string(),
            content: user_msg.clone(),
            extra: Default::default(),
        });
        self.memory_store
            .add_message(user_index, &self.session.messages[user_index]);

        let exclude_cutoff = self
            .session
            .messages
            .len()
            .saturating_sub(self.prompt_cfg.max_recent_messages);

        // Local retrieval (RAG): memory + older snippets.
        let retrieved: RetrievedContext = self.memory_store.retrieve_context(
            &user_msg,
            self.prompt_cfg.max_memory_items,
            self.prompt_cfg.max_recall_snippets,
            Some(exclude_cutoff),
        );

        let remote_messages = build_remote_messages_with_retrieval(
            &self.session,
            &retrieved,
            self.token_class,
            self.redact_mode,
            &self.extra_terms,
            &mut self.redactor,
            &self.prompt_cfg,
        );

        let ticket = self.ticket_source.next_ticket(self.token_class)?;

        let req = InferenceRequest {
            request_id: Uuid::new_v4(),
            model: self.model.clone(),
            messages: remote_messages,
            max_tokens: None,
            temperature: None,
            stream: None,
            token_class: self.token_class,
            ticket,
            provider_options: Default::default(),
        };

        let req_json = serde_json::to_vec(&req).context("serialize request")?;
        let (env, ctx) =
            seal_request_for_gateway(self.gateway_public_bytes, self.token_class, &req_json)
                .context("encrypt request")?;

        info!(
            "sending request_id={} token_class={:?}",
            req.request_id, self.token_class
        );

        let resp = self
            .http
            .post(&self.endpoint_url)
            .json(&env)
            .send()
            .await
            .context("send request")?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("read response")?;

        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            anyhow::bail!("HTTP {}: {}", status, body);
        }

        let resp_env: zk_llm_common::envelope::Envelope =
            serde_json::from_slice(&bytes).context("parse response envelope")?;
        let plaintext = ctx.open_response(&resp_env).context("decrypt response")?;
        let payload: GatewayEnvelopePayload =
            serde_json::from_slice(&plaintext).context("parse payload")?;

        match payload {
            GatewayEnvelopePayload::Ok { response } => {
                // Rehydrate placeholders for local display and local storage.
                let out = self.redactor.rehydrate(&response.output);

                let assistant_index = self.session.messages.len();
                self.session.messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: out.clone(),
                    extra: Default::default(),
                });
                self.memory_store
                    .add_message(assistant_index, &self.session.messages[assistant_index]);

                // Update local rolling summary.
                self.update_summary().await;

                // Persist session frequently in personal-agent use.
                self.session.redaction = self.redactor.state().clone();
                self.persist();
                Ok(out)
            }
            GatewayEnvelopePayload::Err { error } => {
                anyhow::bail!("gateway error: {} - {}", error.code, error.message);
            }
        }
    }

    async fn update_summary(&mut self) {
        // Build a redacted representation of the most recent turn for summarization.
        let turn = self
            .session
            .messages
            .iter()
            .rev()
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        let mut turn_redacted = Vec::new();
        for m in turn.into_iter().rev() {
            turn_redacted.push(ChatMessage {
                role: m.role,
                content: self
                    .redactor
                    .redact(&m.content, self.redact_mode, &self.extra_terms),
                extra: Default::default(),
            });
        }

        if let Some(local) = &self.local_ai {
            match local
                .update_summary(&self.session.summary, &turn_redacted)
                .await
            {
                Ok(s) => {
                    self.session.summary = s;
                    return;
                }
                Err(e) => {
                    warn!(
                        "local summarizer failed; falling back to naive summary: {}",
                        e
                    );
                }
            }
        }

        // Naive fallback summary: append recent turn, keep last ~4000 chars.
        let mut add = String::new();
        for m in &turn_redacted {
            let snippet: String = m.content.chars().take(300).collect();
            add.push_str(&format!("- {}: {}\n", m.role, snippet));
        }
        self.session.summary.push_str(&add);
        if self.session.summary.len() > 4000 {
            let keep = self.session.summary.len() - 4000;
            self.session.summary = self.session.summary.chars().skip(keep).collect();
        }
    }

    /// A small interactive REPL loop.
    pub async fn repl(&mut self) -> Result<()> {
        println!("Interactive mode. Commands: /help, /exit, /remember <text>, /memory, /search <query>, /redact <term>, /system <prompt>");
        loop {
            print!("> ");
            io::stdout().flush().ok();
            let mut line = String::new();
            io::stdin().read_line(&mut line).context("read stdin")?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line == "/exit" || line == "/quit" {
                break;
            }
            if line == "/help" {
                println!(
                    "/exit | /quit\n  Exit\n\n/remember <text>\n  Store a memory item locally\n\n/memory\n  List stored memory\n\n/search <query>\n  Search memory and older messages locally\n\n/redact <term>\n  Add a custom term to redact\n\n/system <prompt>\n  Set the system prompt (local)\n"
                );
                continue;
            }
            if let Some(rest) = line.strip_prefix("/remember ") {
                self.remember(rest.to_string(), vec![]);
                println!("(stored memory item)");
                continue;
            }
            if line == "/memory" {
                if self.session.memory.is_empty() {
                    println!("(no memory items)");
                } else {
                    for (i, m) in self.session.memory.iter().enumerate() {
                        let snip: String = m.text.chars().take(120).collect();
                        println!("{}. {}", i + 1, snip);
                    }
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("/search ") {
                let exclude_cutoff = self
                    .session
                    .messages
                    .len()
                    .saturating_sub(self.prompt_cfg.max_recent_messages);
                let ctx = self
                    .memory_store
                    .retrieve_context(rest, 10, 10, Some(exclude_cutoff));
                if ctx.memories.is_empty() && ctx.recall.is_empty() {
                    println!("(no hits)");
                } else {
                    if !ctx.memories.is_empty() {
                        println!("[Memory]");
                        for (i, d) in ctx.memories.iter().enumerate() {
                            let snip: String = d.text.chars().take(160).collect();
                            println!("- M{}: {}", i + 1, snip);
                        }
                    }
                    if !ctx.recall.is_empty() {
                        println!("[Recall]");
                        for (i, m) in ctx.recall.iter().enumerate() {
                            let snip: String = m.content.chars().take(160).collect();
                            println!("- R{} {}: {}", i + 1, m.role, snip);
                        }
                    }
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("/redact ") {
                self.add_redaction_term(rest.to_string());
                println!("(added custom redaction term)");
                continue;
            }
            if let Some(rest) = line.strip_prefix("/system ") {
                self.set_system_prompt(rest.to_string());
                println!("(updated system prompt)");
                continue;
            }

            match self.send_user_message(line.to_string()).await {
                Ok(out) => println!("{}", out),
                Err(e) => eprintln!("error: {:#}", e),
            }
        }
        Ok(())
    }
}
