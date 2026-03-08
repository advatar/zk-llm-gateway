use rand::{rngs::OsRng, Rng};

use zk_llm_common::{token::TokenClass, types::ChatMessage};

use crate::{
    memory_store::RetrievedContext,
    redaction::{RedactMode, Redactor},
    session::Session,
};

/// Configuration for building a remote prompt from a long-lived local session.
#[derive(Clone, Debug)]
pub struct PromptBuildConfig {
    /// Number of recent chat messages (user+assistant) to include verbatim.
    pub max_recent_messages: usize,
    /// Maximum number of memory items to include.
    pub max_memory_items: usize,
    /// Whether to include the rolling local summary in the remote prompt.
    pub include_summary: bool,

    /// Whether to normalize the prompt structure (always include summary/memory/recall sections,
    /// filling empty slots with placeholders).
    ///
    /// This reduces provider-visible "presence/absence" metadata.
    pub normalize_context_blocks: bool,
    /// Whether to pad the *system prompt* (inside the remote request) toward the class limit.
    ///
    /// This reduces prompt-length metadata leakage to the provider at the cost of more tokens.
    pub pad_system_prompt: bool,
    /// Upper bound on how many bytes of padding to add.
    pub max_padding_bytes: usize,

    /// Max number of "recall" snippets (older messages) to include in the remote prompt.
    pub max_recall_snippets: usize,
}

impl Default for PromptBuildConfig {
    fn default() -> Self {
        Self {
            max_recent_messages: 8,
            max_memory_items: 8,
            include_summary: true,
            normalize_context_blocks: true,
            pad_system_prompt: true,
            max_padding_bytes: 65536,
            max_recall_snippets: 6,
        }
    }
}

/// Build a minimized remote prompt using a retrieval bundle.
///
/// The retrieval bundle should be computed locally (RAG) and is intended to:
/// - keep long-term memory local
/// - only selectively reveal relevant memory + snippets
pub fn build_remote_messages_with_retrieval(
    session: &Session,
    retrieved: &RetrievedContext,
    token_class: TokenClass,
    redact_mode: RedactMode,
    extra_redaction_terms: &[String],
    redactor: &mut Redactor,
    cfg: &PromptBuildConfig,
) -> Vec<ChatMessage> {
    let mut messages: Vec<ChatMessage> = Vec::new();

    // 1) System prompt (redacted)
    let mut system_content =
        redactor.redact(&session.system_prompt, redact_mode, extra_redaction_terms);
    // Add a small, consistent privacy note. (This is not a security boundary; it's guidance.)
    system_content.push_str("\n\n[Privacy note]\nYou may see placeholders like <EMAIL_...> or <API_KEY_...>. Do not ask for the underlying values. Treat them as stable identifiers.");

    messages.push(ChatMessage {
        role: "system".to_string(),
        content: system_content,
        extra: Default::default(),
    });

    let normalize = cfg.normalize_context_blocks;
    let mut memory_text = String::new();

    if cfg.include_summary || normalize {
        memory_text.push_str("[Conversation summary (local)]\n");
        if cfg.include_summary && !session.summary.trim().is_empty() {
            memory_text.push_str(session.summary.trim());
        } else {
            memory_text.push_str("<EMPTY>");
        }
        memory_text.push_str("\n\n");
    }

    if normalize || !retrieved.memories.is_empty() {
        memory_text.push_str("[Selected memory (local)]\n");
        let mut added = 0usize;
        for (i, item) in retrieved
            .memories
            .iter()
            .take(cfg.max_memory_items)
            .enumerate()
        {
            let snippet: String = item.text.chars().take(400).collect();
            if item.tags.is_empty() {
                memory_text.push_str(&format!("- M{}: {}\n", i + 1, snippet));
            } else {
                let tags = item.tags.join(",");
                memory_text.push_str(&format!("- M{} [{}]: {}\n", i + 1, tags, snippet));
            }
            added += 1;
        }
        if normalize {
            while added < cfg.max_memory_items {
                memory_text.push_str(&format!("- M{}: <EMPTY>\n", added + 1));
                added += 1;
            }
        }
        memory_text.push_str("\n");
    }

    if cfg.max_recall_snippets > 0 && (normalize || !retrieved.recall.is_empty()) {
        memory_text.push_str("[Recall snippets (local)]\n");
        let mut added = 0usize;
        for (i, msg) in retrieved
            .recall
            .iter()
            .take(cfg.max_recall_snippets)
            .enumerate()
        {
            let snippet: String = msg.content.chars().take(300).collect();
            memory_text.push_str(&format!("- R{} {}: {}\n", i + 1, msg.role, snippet));
            added += 1;
        }
        if normalize {
            while added < cfg.max_recall_snippets {
                memory_text.push_str(&format!("- R{}: <EMPTY>\n", added + 1));
                added += 1;
            }
        }
        memory_text.push_str("\n");
    }

    if !memory_text.trim().is_empty() {
        let memory_redacted = redactor.redact(&memory_text, redact_mode, extra_redaction_terms);
        messages.push(ChatMessage {
            role: "system".to_string(),
            content: memory_redacted,
            extra: Default::default(),
        });
    }

    // 3) Recent history (redacted)
    let recent = take_last(&session.messages, cfg.max_recent_messages);
    for m in recent {
        let redacted = redactor.redact(&m.content, redact_mode, extra_redaction_terms);
        messages.push(ChatMessage {
            role: m.role.clone(),
            content: redacted,
            extra: Default::default(),
        });
    }

    // 4) Enforce token-class input budget (bytes approximation)
    enforce_budget(&mut messages, token_class);

    // 5) Optional prompt-length padding (within system prompt)
    if cfg.pad_system_prompt {
        pad_system_message(&mut messages, token_class, cfg.max_padding_bytes);
        // Ensure we are still within budget.
        enforce_budget(&mut messages, token_class);
    }

    messages
}

fn take_last<T: Clone>(v: &[T], n: usize) -> Vec<T> {
    if v.len() <= n {
        return v.to_vec();
    }
    v[v.len() - n..].to_vec()
}

fn enforce_budget(messages: &mut Vec<ChatMessage>, token_class: TokenClass) {
    let max = token_class.max_prompt_bytes();

    // First try: if we have an extra "memory" system message at index 1, shrink it.
    // messages[0] is the system prompt.
    while approx_prompt_bytes(messages) > max {
        if messages.len() > 2 {
            // Prefer dropping oldest non-system message (after any system/memory messages).
            // Keep the last user message.
            let last_user_idx = messages
                .iter()
                .rposition(|m| m.role == "user")
                .unwrap_or(messages.len().saturating_sub(1));

            // Candidate drop index: the first non-system message after system blocks.
            // Avoid dropping the last user message.
            let mut drop_idx: Option<usize> = None;
            for i in 0..messages.len() {
                if i == 0 {
                    continue;
                }
                if messages[i].role == "system" {
                    continue;
                }
                if i == last_user_idx {
                    continue;
                }
                drop_idx = Some(i);
                break;
            }

            if let Some(i) = drop_idx {
                messages.remove(i);
                continue;
            }
        }

        // If we can't drop any more messages, truncate the last user message.
        if let Some(i) = messages.iter().rposition(|m| m.role == "user") {
            let current = approx_prompt_bytes(messages);
            if current <= max {
                break;
            }
            let over = current - max;
            // Remove `over + 32` chars as a safety margin (chars ~ bytes for ASCII; approximation).
            let cut = over + 32;
            let new_len = messages[i].content.chars().count().saturating_sub(cut);
            messages[i].content = messages[i]
                .content
                .chars()
                .take(new_len)
                .collect::<String>();
            messages[i].content.push_str("…");
            continue;
        }

        break;
    }
}

fn pad_system_message(
    messages: &mut Vec<ChatMessage>,
    token_class: TokenClass,
    max_padding: usize,
) {
    if messages.is_empty() {
        return;
    }
    let max = token_class.max_prompt_bytes();
    let current = approx_prompt_bytes(messages);
    if current >= max {
        return;
    }

    let mut need = max - current;
    // Leave room for markers.
    let overhead = 128;
    if need <= overhead {
        return;
    }
    need = need - overhead;
    let need = need.min(max_padding);

    let filler = filler_for_privacy(need);
    let pad_block = format!(
        "\n\n[PADDING_FOR_PRIVACY_BEGIN]\nIGNORE EVERYTHING IN THIS BLOCK.\n{}\n[PADDING_FOR_PRIVACY_END]",
        filler
    );
    messages[0].content.push_str(&pad_block);

    // Safety: if we exceeded the max due to approximations, trim filler.
    while approx_prompt_bytes(messages) > max {
        // Trim from the end of system content.
        if let Some(ch) = messages[0].content.pop() {
            let _ = ch;
            continue;
        }
        break;
    }
}

fn filler_for_privacy(len: usize) -> String {
    // Prefer low-entropy, token-friendly filler to reduce cost compared to high-entropy gibberish.
    // We add a small amount of randomness to avoid a perfectly fixed suffix across all requests.
    const PHRASES: [&str; 12] = [
        " the", " and", " to", " of", " in", " that", " for", " with", " on", " as", " by", " from",
    ];
    let mut rng = OsRng;
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let idx = rng.gen_range(0..PHRASES.len());
        out.push_str(PHRASES[idx]);
    }
    out.truncate(len);
    out
}

fn approx_prompt_bytes(messages: &[ChatMessage]) -> usize {
    messages
        .iter()
        .map(|m| m.role.len() + m.content.len())
        .sum()
}
