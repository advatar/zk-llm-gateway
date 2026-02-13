use std::collections::HashMap;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::ValueEnum;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// How aggressively to redact sensitive content *before* sending prompts to a remote provider.
///
/// Notes:
/// - `None` maximizes model quality but leaks anything you type.
/// - `Basic` targets common identifiers + secrets (recommended default).
/// - `Strict` is heavier and can reduce usefulness, but reduces re-identification risk.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[clap(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RedactMode {
    None,
    Basic,
    Strict,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    PrivateKey,
    ApiKey,
    Email,
    Phone,
    EthAddress,
    Url,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionEntry {
    pub placeholder: String,
    pub original: String,
    pub kind: RedactionKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionState {
    /// Base64-encoded 32-byte salt.
    pub salt_b64: String,
    /// Persisted placeholder->original mapping (used to rehydrate outputs locally).
    pub entries: Vec<RedactionEntry>,
    /// Explicit terms that the user wants redacted (eg. company name, project name).
    pub custom_terms: Vec<String>,
}

impl RedactionState {
    pub fn new(salt_b64: String) -> Self {
        Self {
            salt_b64,
            entries: Vec::new(),
            custom_terms: Vec::new(),
        }
    }
}

/// Client-side redactor.
///
/// - Redacts sensitive strings deterministically into placeholders.
/// - Stores a reversible mapping locally so that model outputs can be rehydrated for the user.
pub struct Redactor {
    salt: [u8; 32],
    /// placeholder -> original
    rev: HashMap<String, String>,
    state: RedactionState,
}

impl Redactor {
    pub fn from_state(state: RedactionState) -> Result<Self> {
        let salt = decode_b64_32(&state.salt_b64)?;
        let mut rev = HashMap::new();
        for e in &state.entries {
            rev.insert(e.placeholder.clone(), e.original.clone());
        }
        Ok(Self { salt, rev, state })
    }

    pub fn state(&self) -> &RedactionState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut RedactionState {
        &mut self.state
    }

    pub fn add_custom_term(&mut self, term: String) {
        if term.trim().is_empty() {
            return;
        }
        if !self.state.custom_terms.contains(&term) {
            self.state.custom_terms.push(term);
        }
    }

    /// Redact sensitive content in `text` according to `mode`.
    ///
    /// Returns a redacted string with placeholders like `<EMAIL_1a2b3c4d>`.
    pub fn redact(&mut self, text: &str, mode: RedactMode, extra_terms: &[String]) -> String {
        if mode == RedactMode::None {
            return text.to_string();
        }

        // Run higher-risk patterns first (multi-line blocks, API keys) so nested content doesn't leak.
        let mut out = text.to_string();

        out = redact_regex(
            self,
            &out,
            &RE_PRIVATE_KEY_BLOCK,
            RedactionKind::PrivateKey,
            "PRIVATE_KEY",
        );
        out = redact_regex(self, &out, &RE_OPENAI_KEY, RedactionKind::ApiKey, "API_KEY");

        // Identifiers: for a personal-agent use case these can be highly identifying.
        out = redact_regex(self, &out, &RE_EMAIL, RedactionKind::Email, "EMAIL");
        out = redact_regex(self, &out, &RE_PHONE, RedactionKind::Phone, "PHONE");
        out = redact_regex(
            self,
            &out,
            &RE_ETH_ADDRESS,
            RedactionKind::EthAddress,
            "ETH_ADDR",
        );

        if mode == RedactMode::Strict {
            out = redact_regex(self, &out, &RE_URL, RedactionKind::Url, "URL");
        }

        // Custom exact-match terms.
        let all_custom_terms: Vec<String> = self
            .state
            .custom_terms
            .iter()
            .chain(extra_terms.iter())
            .cloned()
            .collect();
        for term in all_custom_terms {
            if term.trim().is_empty() {
                continue;
            }
            out = redact_literal(self, &out, &term, RedactionKind::Custom, "CUSTOM");
        }

        out
    }

    /// Rehydrate placeholders in `text` back to their original values.
    ///
    /// This is a *local-only* operation so the user sees their true values,
    /// while the remote provider only ever sees placeholders.
    pub fn rehydrate(&self, text: &str) -> String {
        if self.rev.is_empty() {
            return text.to_string();
        }

        // Replace longer placeholders first to avoid accidental partial overlaps.
        let mut keys: Vec<&String> = self.rev.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));

        let mut out = text.to_string();
        for ph in keys {
            if let Some(orig) = self.rev.get(ph) {
                out = out.replace(ph, orig);
            }
        }
        out
    }

    fn upsert_mapping(&mut self, placeholder: String, original: String, kind: RedactionKind) {
        if self.rev.contains_key(&placeholder) {
            return;
        }

        self.rev.insert(placeholder.clone(), original.clone());
        self.state.entries.push(RedactionEntry {
            placeholder,
            original,
            kind,
        });
    }

    fn placeholder_for(&self, tag: &str, original: &str) -> String {
        let mut h = sha2::Sha256::new();
        h.update(&self.salt);
        h.update(tag.as_bytes());
        h.update(original.as_bytes());
        let digest = h.finalize();
        let short = &digest[..8];
        format!("<{}_{}>", tag, to_hex(short))
    }
}

fn redact_regex(
    red: &mut Redactor,
    input: &str,
    re: &Regex,
    kind: RedactionKind,
    tag: &str,
) -> String {
    re.replace_all(input, |caps: &regex::Captures| {
        let m = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        let ph = red.placeholder_for(tag, m);
        red.upsert_mapping(ph.clone(), m.to_string(), kind.clone());
        ph
    })
    .to_string()
}

fn redact_literal(
    red: &mut Redactor,
    input: &str,
    literal: &str,
    kind: RedactionKind,
    tag: &str,
) -> String {
    if !input.contains(literal) {
        return input.to_string();
    }
    let ph = red.placeholder_for(tag, literal);
    red.upsert_mapping(ph.clone(), literal.to_string(), kind);
    input.replace(literal, &ph)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_b64_32(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("salt must be 32 bytes"))?;
    Ok(arr)
}

static RE_PRIVATE_KEY_BLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .unwrap()
});

static RE_OPENAI_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9]{16,}").unwrap());

static RE_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap());

static RE_PHONE: Lazy<Regex> = Lazy::new(|| {
    // Very permissive, but avoids many false negatives. Tune for your environment.
    Regex::new(r"\+?\d[\d\s\-()]{7,}\d").unwrap()
});

static RE_ETH_ADDRESS: Lazy<Regex> = Lazy::new(|| Regex::new(r"0x[a-fA-F0-9]{40}").unwrap());

static RE_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r"https?://[^\s]+").unwrap());
