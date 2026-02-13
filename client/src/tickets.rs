use std::{fs, path::PathBuf, sync::Mutex};

use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};

use zk_llm_common::{
    token::TokenClass,
    zk::{B64Bytes, ZkTicket},
};

/// A source of per-call usage tickets.
///
/// In a real ZK usage-credits system, this would be backed by:
/// - a deposit/commitment,
/// - a proof generator, and
/// - possibly a refund-ticket mechanism.
///
/// For this repo we provide:
/// - `DummyTicketSource`: random bytes (dev only)
/// - `FileTicketSource`: consume pre-minted tickets from a JSON file
pub trait TicketSource: Send + Sync {
    fn next_ticket(&self, token_class: TokenClass) -> Result<ZkTicket>;
}

#[derive(Default)]
pub struct DummyTicketSource;

impl TicketSource for DummyTicketSource {
    fn next_ticket(&self, token_class: TokenClass) -> Result<ZkTicket> {
        let mut root = vec![0u8; 32];
        let mut nullifier = vec![0u8; 32];
        let mut proof = vec![0u8; 64];
        OsRng.fill_bytes(&mut root);
        OsRng.fill_bytes(&mut nullifier);
        OsRng.fill_bytes(&mut proof);

        Ok(ZkTicket {
            commitment_root: B64Bytes(root),
            nullifier: B64Bytes(nullifier),
            token_class,
            proof: B64Bytes(proof),
        })
    }
}

pub struct FileTicketSource {
    path: PathBuf,
    tickets: Mutex<Vec<ZkTicket>>,
}

impl FileTicketSource {
    pub fn load(path: PathBuf) -> Result<Self> {
        let bytes =
            fs::read(&path).with_context(|| format!("read ticket file {}", path.display()))?;
        let tickets: Vec<ZkTicket> = serde_json::from_slice(&bytes)
            .context("parse ticket file (expected JSON array of ZkTicket)")?;
        Ok(Self {
            path,
            tickets: Mutex::new(tickets),
        })
    }

    fn persist(&self, tickets: &[ZkTicket]) {
        // Best-effort persistence; avoid crashing the client if this fails.
        if let Ok(bytes) = serde_json::to_vec_pretty(tickets) {
            let _ = fs::write(&self.path, bytes);
        }
    }
}

impl TicketSource for FileTicketSource {
    fn next_ticket(&self, token_class: TokenClass) -> Result<ZkTicket> {
        let mut guard = self.tickets.lock().unwrap();
        let idx = guard
            .iter()
            .position(|t| t.token_class == token_class)
            .or_else(|| guard.iter().position(|_t| true));

        let Some(i) = idx else {
            anyhow::bail!("ticket file is empty")
        };

        let ticket = guard.remove(i);
        self.persist(&guard);
        Ok(ticket)
    }
}
