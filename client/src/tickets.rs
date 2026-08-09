use std::{fs, path::PathBuf, sync::Mutex};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;

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
    fn next_ticket(&self, token_class: TokenClass, request_commitment: &[u8]) -> Result<ZkTicket>;
}

#[derive(Default)]
pub struct DummyTicketSource;

impl TicketSource for DummyTicketSource {
    fn next_ticket(&self, token_class: TokenClass, request_commitment: &[u8]) -> Result<ZkTicket> {
        let mut nullifier = vec![0u8; 32];
        let mut proof = vec![0u8; 64];
        OsRng.fill_bytes(&mut nullifier);
        OsRng.fill_bytes(&mut proof);

        Ok(ZkTicket {
            commitment_root: B64Bytes(request_commitment.to_vec()),
            nullifier: B64Bytes(nullifier),
            token_class,
            proof: B64Bytes(proof),
        })
    }
}

/// Generates protocol-shaped evidence accepted only by ZeroK's Docker-local Actum fixture.
#[derive(Default)]
pub struct ActumDevTicketSource;

impl TicketSource for ActumDevTicketSource {
    fn next_ticket(&self, token_class: TokenClass, request_commitment: &[u8]) -> Result<ZkTicket> {
        if request_commitment.len() != 32 {
            anyhow::bail!("Actum request commitment must be 32 bytes")
        }
        let mut replay_identifier = vec![0u8; 48];
        let mut authorization_id = vec![0u8; 48];
        OsRng.fill_bytes(&mut replay_identifier);
        OsRng.fill_bytes(&mut authorization_id);
        let evidence = serde_json::to_vec(&json!({
            "schema": "actum.payment-finality.v1",
            "request_commitment_b64": B64.encode(request_commitment),
            "replay_identifier_b64": B64.encode(&replay_identifier),
            "token_class": token_class,
            "finalized": true,
            "authorization_id_b64": B64.encode(&authorization_id),
        }))?;
        Ok(ZkTicket {
            commitment_root: B64Bytes(request_commitment.to_vec()),
            nullifier: B64Bytes(replay_identifier),
            token_class,
            proof: B64Bytes(evidence),
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
    fn next_ticket(&self, token_class: TokenClass, request_commitment: &[u8]) -> Result<ZkTicket> {
        let mut guard = self.tickets.lock().unwrap();
        let idx = guard
            .iter()
            .position(|t| t.token_class == token_class)
            .or_else(|| guard.iter().position(|_t| true));

        let Some(i) = idx else {
            anyhow::bail!("ticket file is empty")
        };

        let ticket = guard.remove(i);
        if ticket.commitment_root.0 != request_commitment {
            anyhow::bail!("issued ticket is not bound to the exact inference request")
        }
        self.persist(&guard);
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actum_dev_ticket_binds_exact_request_commitment() {
        let commitment = vec![3; 32];
        let ticket = ActumDevTicketSource
            .next_ticket(TokenClass::C512, &commitment)
            .unwrap();
        assert_eq!(ticket.commitment_root.0, commitment);
        let evidence: serde_json::Value = serde_json::from_slice(&ticket.proof.0).unwrap();
        assert_eq!(evidence["schema"], "actum.payment-finality.v1");
        assert_eq!(evidence["finalized"], true);
    }
}
