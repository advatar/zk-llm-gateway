use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use zk_llm_common::types::ChatMessage;

use crate::session::MemoryItem;

/// A lightweight local "RAG" index for a personal-agent session.
///
/// Why this exists:
/// - In a long-lived personal-agent chat, you need recall.
/// - Sending the full conversation history or full private memory to a remote model
///   is a privacy leak and increases linkability.
///
/// This module provides a simple, dependency-light full-text retrieval system
/// (BM25-style scoring) so the client can:
/// - keep memory local
/// - retrieve only the few most relevant items/snippets
/// - include only those in the remote prompt
///
/// NOTE: This is not an embedding index. It's intentionally simple and local-first.

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocKind {
    Memory,
    Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Doc {
    pub kind: DocKind,
    pub id: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub role: Option<String>,
    /// For message docs, the index into the session's `messages` array.
    #[serde(default)]
    pub msg_index: Option<usize>,
    pub text: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub score: f32,
    pub doc: Doc,
}

/// A retrieval bundle used by prompt building.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RetrievedContext {
    #[serde(default)]
    pub memories: Vec<Doc>,
    #[serde(default)]
    pub recall: Vec<ChatMessage>,
}

/// A small, local BM25-style index.
///
/// This is meant to be:
/// - deterministic
/// - quick to rebuild from a local session file
/// - trivial to ship in hackathon code
pub struct MemoryStore {
    docs: Vec<Doc>,
    /// token -> postings list of (doc_idx, term_frequency)
    inverted: HashMap<String, Vec<(usize, u32)>>,
    /// doc_idx -> token length
    doc_len: Vec<u32>,
    avg_doc_len: f32,
    /// BM25 parameters
    k1: f32,
    b: f32,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            docs: Vec::new(),
            inverted: HashMap::new(),
            doc_len: Vec::new(),
            avg_doc_len: 0.0,
            k1: 1.2,
            b: 0.75,
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the index from scratch.
    ///
    /// Use this at startup (after loading a session file).
    pub fn rebuild_from_session(
        &mut self,
        memory: &[MemoryItem],
        messages: &[ChatMessage],
        index_messages: bool,
        max_messages: usize,
    ) {
        *self = Self::default();

        for m in memory {
            self.add_memory_item(m);
        }

        if index_messages {
            // Index most recent messages up to a cap.
            let start = messages.len().saturating_sub(max_messages);
            for (i, msg) in messages.iter().enumerate().skip(start) {
                self.add_message(i, msg);
            }
        }

        self.recompute_avg_len();
    }

    pub fn add_memory_item(&mut self, item: &MemoryItem) {
        let doc = Doc {
            kind: DocKind::Memory,
            id: item.id.to_string(),
            created_at_ms: item.created_at_ms,
            role: None,
            msg_index: None,
            text: item.text.clone(),
            tags: item.tags.clone(),
        };
        self.add_doc(doc);
    }

    pub fn add_message(&mut self, msg_index: usize, msg: &ChatMessage) {
        let doc = Doc {
            kind: DocKind::Message,
            id: format!("msg:{}", msg_index),
            created_at_ms: 0,
            role: Some(msg.role.clone()),
            msg_index: Some(msg_index),
            text: msg.content.clone(),
            tags: Vec::new(),
        };
        self.add_doc(doc);
    }

    fn add_doc(&mut self, doc: Doc) {
        let idx = self.docs.len();
        let tokens = tokenize_for_index(&doc.text, &doc.tags);
        let mut tf: HashMap<String, u32> = HashMap::new();
        for t in tokens {
            *tf.entry(t).or_insert(0) += 1;
        }

        let len = tf.values().sum::<u32>();
        self.doc_len.push(len.max(1));

        for (term, freq) in tf {
            self.inverted.entry(term).or_default().push((idx, freq));
        }

        self.docs.push(doc);
        // Update avg incrementally (cheap). For correctness, it's fine; rebuild calls recompute.
        self.recompute_avg_len();
    }

    fn recompute_avg_len(&mut self) {
        if self.doc_len.is_empty() {
            self.avg_doc_len = 0.0;
            return;
        }
        let sum = self.doc_len.iter().map(|v| *v as f32).sum::<f32>();
        self.avg_doc_len = sum / (self.doc_len.len() as f32);
    }

    pub fn search(
        &self,
        query: &str,
        limit: usize,
        kind_filter: Option<DocKind>,
        // If set, exclude message docs with msg_index >= this value.
        exclude_messages_from_index: Option<usize>,
    ) -> Vec<SearchResult> {
        if limit == 0 {
            return Vec::new();
        }
        let qterms = tokenize_query(query);
        if qterms.is_empty() {
            return Vec::new();
        }

        let n_docs = self.docs.len() as f32;
        if n_docs == 0.0 {
            return Vec::new();
        }

        let mut scores: HashMap<usize, f32> = HashMap::new();
        let avgdl = self.avg_doc_len.max(1.0);

        for term in qterms {
            let Some(postings) = self.inverted.get(&term) else {
                continue;
            };
            let df = postings.len() as f32;
            if df == 0.0 {
                continue;
            }

            // BM25-ish IDF
            let idf = ((n_docs - df + 0.5) / (df + 0.5) + 1.0).ln();

            for (doc_idx, tf) in postings {
                if let Some(k) = &kind_filter {
                    if &self.docs[*doc_idx].kind != k {
                        continue;
                    }
                }

                if let Some(cutoff) = exclude_messages_from_index {
                    if self.docs[*doc_idx].kind == DocKind::Message {
                        if let Some(mi) = self.docs[*doc_idx].msg_index {
                            if mi >= cutoff {
                                continue;
                            }
                        }
                    }
                }

                let dl = self.doc_len.get(*doc_idx).copied().unwrap_or(1) as f32;
                let tf = *tf as f32;
                let denom = tf + self.k1 * (1.0 - self.b + self.b * (dl / avgdl));
                let tf_norm = (tf * (self.k1 + 1.0)) / denom;
                let add = idf * tf_norm;
                *scores.entry(*doc_idx).or_insert(0.0) += add;
            }
        }

        let mut out: Vec<SearchResult> = scores
            .into_iter()
            .map(|(idx, score)| SearchResult {
                score,
                doc: self.docs[idx].clone(),
            })
            .collect();

        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(limit);
        out
    }

    /// Retrieve a prompt-friendly bundle:
    /// - top `max_memory_items` memory docs
    /// - top `max_recall_snippets` older message snippets
    ///
    /// `exclude_recent_messages` is used so we don't "recall" what we're already including
    /// verbatim as the last N messages.
    pub fn retrieve_context(
        &self,
        query: &str,
        max_memory_items: usize,
        max_recall_snippets: usize,
        exclude_recent_messages_cutoff: Option<usize>,
    ) -> RetrievedContext {
        let memories = self
            .search(query, max_memory_items, Some(DocKind::Memory), None)
            .into_iter()
            .map(|r| r.doc)
            .collect::<Vec<_>>();

        let mut recall_msgs: Vec<ChatMessage> = Vec::new();
        if max_recall_snippets > 0 {
            let recall = self.search(
                query,
                max_recall_snippets,
                Some(DocKind::Message),
                exclude_recent_messages_cutoff,
            );

            for r in recall {
                let role = r.doc.role.clone().unwrap_or_else(|| "unknown".to_string());
                let mut content: String = r.doc.text.chars().take(400).collect();
                if r.doc.text.chars().count() > 400 {
                    content.push('…');
                }
                recall_msgs.push(ChatMessage {
                    role,
                    content,
                    extra: Default::default(),
                });
            }
        }

        RetrievedContext {
            memories,
            recall: recall_msgs,
        }
    }
}

fn tokenize_for_index(text: &str, tags: &[String]) -> Vec<String> {
    let mut toks = tokenize(text);
    for t in tags {
        let tag = t.trim().to_lowercase();
        if !tag.is_empty() {
            toks.push(format!("tag:{}", tag));
        }
    }
    toks
}

fn tokenize_query(q: &str) -> Vec<String> {
    // Deduplicate query tokens so repeated words don't dominate.
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for t in tokenize(q) {
        if seen.insert(t.clone()) {
            out.push(t);
        }
    }
    out
}

fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter_map(|w| {
            let w = w.trim();
            if w.len() < 3 {
                return None;
            }
            if is_stopword(w) {
                return None;
            }
            Some(w.to_string())
        })
        .collect()
}

fn is_stopword(w: &str) -> bool {
    // Tiny stopword list; keep it small and predictable.
    matches!(
        w,
        "the"
            | "and"
            | "for"
            | "with"
            | "this"
            | "that"
            | "from"
            | "have"
            | "you"
            | "your"
            | "are"
            | "was"
            | "were"
            | "will"
            | "would"
            | "should"
            | "could"
            | "what"
            | "when"
            | "where"
            | "why"
            | "how"
            | "into"
            | "about"
            | "them"
            | "they"
            | "then"
            | "than"
            | "also"
            | "just"
            | "like"
            | "want"
            | "need"
            | "been"
            | "being"
            | "can"
            | "not"
            | "but"
            | "our"
            | "out"
            | "use"
            | "using"
            | "used"
    )
}
