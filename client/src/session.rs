use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

use zk_llm_common::types::ChatMessage;

use crate::redaction::RedactionState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryItem {
    pub id: Uuid,
    pub created_at_ms: i64,
    pub text: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub created_at_ms: i64,
    pub system_prompt: String,

    /// Full conversation history (local-only).
    pub messages: Vec<ChatMessage>,

    /// Stable "memory" items (local-only) that the client can selectively reveal.
    #[serde(default)]
    pub memory: Vec<MemoryItem>,

    /// Rolling local summary (local-only).
    #[serde(default)]
    pub summary: String,

    /// Redaction state (stored locally so outputs can be rehydrated).
    pub redaction: RedactionState,
}

impl Session {
    pub fn new(system_prompt: String) -> Self {
        let created_at_ms = now_ms();
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let salt_b64 = B64.encode(salt);

        Self {
            version: 1,
            created_at_ms,
            system_prompt,
            messages: Vec::new(),
            memory: Vec::new(),
            summary: String::new(),
            redaction: RedactionState::new(salt_b64),
        }
    }

    pub fn push_memory(&mut self, text: String, tags: Vec<String>) {
        self.memory.push(MemoryItem {
            id: Uuid::new_v4(),
            created_at_ms: now_ms(),
            text,
            tags,
        });
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SessionDisk {
    Plain {
        session: Session,
    },
    Encrypted {
        enc_version: u32,
        salt_b64: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },
}

pub fn load_session(path: &Path, session_key: Option<[u8; 32]>) -> Result<Session> {
    let bytes = fs::read(path).with_context(|| format!("read session file {}", path.display()))?;

    // New format with an explicit wrapper.
    if let Ok(w) = serde_json::from_slice::<SessionDisk>(&bytes) {
        return match w {
            SessionDisk::Plain { session } => Ok(session),
            SessionDisk::Encrypted {
                enc_version,
                salt_b64,
                nonce_b64,
                ciphertext_b64,
            } => {
                if enc_version != 1 {
                    anyhow::bail!("unsupported session enc_version={}", enc_version);
                }
                let key =
                    session_key.context("session file is encrypted; provide --session-key-b64")?;
                let salt: [u8; 16] = B64
                    .decode(salt_b64)
                    .context("invalid encrypted session salt")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("encrypted session salt must be 16 bytes"))?;
                let nonce_bytes: [u8; 12] = B64
                    .decode(nonce_b64)
                    .context("invalid encrypted session nonce")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("encrypted session nonce must be 12 bytes"))?;
                let ciphertext = B64
                    .decode(ciphertext_b64)
                    .context("invalid encrypted session ciphertext")?;

                let mut aead_key = derive_session_key(&key, &salt)?;
                let aead = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
                let nonce = Nonce::from_slice(&nonce_bytes);
                let aad = b"zk-llm-session-v1";
                let plaintext = aead
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext.as_ref(),
                            aad,
                        },
                    )
                    .context("session decrypt failed")?;
                aead_key.zeroize();
                let session: Session =
                    serde_json::from_slice(&plaintext).context("parse decrypted session json")?;
                Ok(session)
            }
        };
    }

    // Backward compatibility: previous MVP stored just Vec<ChatMessage>.
    if let Ok(history) = serde_json::from_slice::<Vec<ChatMessage>>(&bytes) {
        let mut s = Session::new("You are a helpful assistant.".to_string());
        s.messages = history;
        return Ok(s);
    }

    anyhow::bail!("unrecognized session file format")
}

pub fn save_session(path: &Path, session: &Session, session_key: Option<[u8; 32]>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }

    if let Some(key) = session_key {
        // Encrypt at rest
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let mut plaintext = serde_json::to_vec(session).context("serialize session")?;
        let mut aead_key = derive_session_key(&key, &salt)?;
        let aead = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = b"zk-llm-session-v1";

        let ciphertext = aead
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad,
                },
            )
            .context("encrypt session failed")?;

        plaintext.zeroize();
        aead_key.zeroize();

        let wrapper = SessionDisk::Encrypted {
            enc_version: 1,
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
        };
        let out = serde_json::to_vec_pretty(&wrapper).context("serialize encrypted wrapper")?;
        fs::write(path, out).with_context(|| format!("write session file {}", path.display()))?;
        return Ok(());
    }

    let wrapper = SessionDisk::Plain {
        session: session.clone(),
    };
    let out = serde_json::to_vec_pretty(&wrapper).context("serialize session wrapper")?;
    fs::write(path, out).with_context(|| format!("write session file {}", path.display()))?;
    Ok(())
}

fn derive_session_key(master: &[u8; 32], salt: &[u8; 16]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut okm = [0u8; 32];
    hk.expand(b"zk-llm-session-v1", &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

pub fn now_ms() -> i64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64) * 1000 + (d.subsec_millis() as i64)
}
