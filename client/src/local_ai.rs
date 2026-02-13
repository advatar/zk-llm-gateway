use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use zk_llm_common::types::ChatMessage;

/// Optional local model helper.
///
/// For the personal-agent use case, running a *local* summarizer lets you keep
/// long-term memory and summarization private while still using a powerful remote model
/// for the main response.
#[derive(Clone, Debug)]
pub struct LocalAiConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Clone)]
pub struct LocalAiClient {
    cfg: LocalAiConfig,
    http: reqwest::Client,
}

impl LocalAiClient {
    pub fn new(cfg: LocalAiConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .context("build local ai http client")?;
        Ok(Self { cfg, http })
    }

    /// Update a rolling summary given the previous summary and the newest turn.
    pub async fn update_summary(
        &self,
        previous_summary: &str,
        new_turn: &[ChatMessage],
    ) -> Result<String> {
        let sys = "You are a privacy-preserving summarizer running on the user's machine.\n\
Update the existing summary with the new turn.\n\
- Keep it short (<= 12 bullet points).\n\
- Prefer generalization over personal details.\n\
- Preserve placeholders like <EMAIL_...>, <API_KEY_...>, <ETH_ADDR_...>.\n\
- Do not add new sensitive details that were not present.";

        let mut turn_text = String::new();
        for m in new_turn {
            let snippet: String = m.content.chars().take(2000).collect();
            turn_text.push_str(&format!("{}: {}\n", m.role, snippet));
        }

        let user = format!(
            "Previous summary:\n{}\n\nNew turn:\n{}\n\nReturn ONLY the updated summary.",
            previous_summary, turn_text
        );

        let body = ProviderChatCompletionRequest {
            model: self.cfg.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: sys.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user,
                },
            ],
            max_tokens: 512,
            temperature: Some(0.0),
        };

        let url = format!(
            "{}/v1/chat/completions",
            self.cfg.base_url.trim_end_matches('/')
        );
        let mut builder = self.http.post(url).json(&body);
        if let Some(key) = &self.cfg.api_key {
            builder = builder.bearer_auth(key);
        }

        let resp = builder.send().await.context("send to local summarizer")?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .context("read local summarizer response")?;
        if !status.is_success() {
            anyhow::bail!("local summarizer returned HTTP {}", status);
        }

        let parsed: ProviderChatCompletionResponse =
            serde_json::from_slice(&bytes).context("parse local summarizer response")?;
        let out = parsed
            .choices
            .get(0)
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();
        Ok(out.trim().to_string())
    }
}

#[derive(Debug, Serialize)]
struct ProviderChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct ProviderChatCompletionResponse {
    choices: Vec<ProviderChoice>,
}

#[derive(Debug, Deserialize)]
struct ProviderChoice {
    message: ProviderMessage,
}

#[derive(Debug, Deserialize)]
struct ProviderMessage {
    content: Option<String>,
}
