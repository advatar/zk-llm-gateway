use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::token::TokenClass;

/// Base64 wrapper for bytes in JSON.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct B64Bytes(pub Vec<u8>);

impl Serialize for B64Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&B64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = B64.decode(s).map_err(D::Error::custom)?;
        Ok(B64Bytes(bytes))
    }
}

/// Anonymous usage authorization for a single call.
///
/// This is the object that a real ZK proof would verify. For the MVP, we keep
/// the structure explicit so it can be wired into a Halo2/Plonk/Groth16 verifier later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTicket {
    /// Merkle root (or other accumulator) of valid commitments.
    pub commitment_root: B64Bytes,

    /// Nullifier unique per ticket. The gateway must ensure this is not reused.
    pub nullifier: B64Bytes,

    /// Billed class that the proof binds to.
    pub token_class: TokenClass,

    /// Opaque proof bytes.
    pub proof: B64Bytes,
}

/// Information returned by a ZK verifier on success.
#[derive(Debug, Clone)]
pub struct VerifiedTicket {
    pub token_class: TokenClass,
    /// A stable identifier for replay protection. Typically H(nullifier).
    pub nullifier_key: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ZkVerifyError {
    #[error("invalid proof")]
    InvalidProof,
    #[error("internal verifier error: {0}")]
    Internal(String),
}

/// Verifies anonymous usage tickets.
///
/// In production, implement this trait using your ZK proof system of choice.
pub trait ZkVerifier: Send + Sync {
    fn verify(&self, ticket: &ZkTicket) -> std::result::Result<VerifiedTicket, ZkVerifyError>;
}

/// A deliberately insecure verifier useful for wiring the gateway end-to-end.
///
/// IMPORTANT: Only enable in local development.
#[derive(Default)]
pub struct DummyVerifier;

impl ZkVerifier for DummyVerifier {
    fn verify(&self, ticket: &ZkTicket) -> std::result::Result<VerifiedTicket, ZkVerifyError> {
        if ticket.proof.0.is_empty() || ticket.nullifier.0.is_empty() {
            return Err(ZkVerifyError::InvalidProof);
        }
        // For dev mode, treat the nullifier itself as the replay key.
        Ok(VerifiedTicket {
            token_class: ticket.token_class,
            nullifier_key: ticket.nullifier.0.clone(),
        })
    }
}

/// Utility: hash a byte slice with SHA-256.
pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

/// Utility: a stable replay key for a ticket.
///
/// Use this rather than raw nullifiers in databases, to reduce the risk that a DB leak
/// gives an attacker useful structure.
pub fn replay_key(ticket: &ZkTicket) -> Vec<u8> {
    sha256(&ticket.nullifier.0)
}

/// Helper to parse JSON and return a ZkTicket (useful in tests).
pub fn parse_ticket_json(json: &str) -> Result<ZkTicket> {
    Ok(serde_json::from_str(json)?)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_ticket_json, replay_key, sha256, B64Bytes, DummyVerifier, ZkTicket, ZkVerifier,
    };
    use crate::token::TokenClass;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    fn make_ticket(token_class: TokenClass, nullifier: Vec<u8>, proof: Vec<u8>) -> ZkTicket {
        ZkTicket {
            commitment_root: B64Bytes(vec![9u8; 32]),
            nullifier: B64Bytes(nullifier),
            token_class,
            proof: B64Bytes(proof),
        }
    }

    #[test]
    fn dummy_verifier_accepts_minimal_valid_ticket() {
        let verifier = DummyVerifier;
        let ticket = make_ticket(TokenClass::C512, vec![1u8, 2, 3], vec![7u8]);

        let verified = verifier.verify(&ticket).expect("ticket should verify");
        assert_eq!(verified.token_class, TokenClass::C512);
        assert_eq!(verified.nullifier_key, vec![1u8, 2, 3]);
    }

    #[test]
    fn dummy_verifier_rejects_empty_fields() {
        let verifier = DummyVerifier;
        let empty_proof = make_ticket(TokenClass::C256, vec![1u8], vec![]);
        assert!(verifier.verify(&empty_proof).is_err());

        let empty_nullifier = make_ticket(TokenClass::C256, vec![], vec![1u8]);
        assert!(verifier.verify(&empty_nullifier).is_err());
    }

    #[test]
    fn replay_key_hashes_nullifier() {
        let ticket = make_ticket(TokenClass::C1024, vec![4u8, 5, 6], vec![1u8]);
        assert_eq!(replay_key(&ticket), sha256(&[4u8, 5, 6]));
    }

    #[test]
    fn parse_ticket_json_decodes_base64_fields() {
        let json = format!(
            r#"{{
                "commitment_root": "{}",
                "nullifier": "{}",
                "token_class": "c2048",
                "proof": "{}"
            }}"#,
            B64.encode([8u8; 4]),
            B64.encode([1u8, 2, 3, 4]),
            B64.encode([7u8, 7, 7])
        );

        let ticket = parse_ticket_json(&json).expect("json should parse");
        assert_eq!(ticket.token_class, TokenClass::C2048);
        assert_eq!(ticket.commitment_root.0, vec![8u8; 4]);
        assert_eq!(ticket.nullifier.0, vec![1u8, 2, 3, 4]);
        assert_eq!(ticket.proof.0, vec![7u8, 7, 7]);
    }
}
