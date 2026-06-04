use std::path::PathBuf;

#[cfg(feature = "halo2")]
use anyhow::Context;
use anyhow::Result;

#[cfg(feature = "halo2")]
use zk_llm_common::zk::replay_key;
use zk_llm_common::zk::{VerifiedTicket, ZkTicket, ZkVerifier, ZkVerifyError};

/// Configuration for a Halo2/Plonk verifier.
///
/// The exact meaning of these files depends on the circuit you use. A typical setup
/// uses some form of "params" (KZG/IPA parameters) plus a verifying key.
#[derive(Clone, Debug)]
pub struct Halo2PlonkVerifierConfig {
    /// Path to a verifying key file (format is circuit-specific).
    pub verifying_key_path: PathBuf,
    /// Optional path to params (KZG/IPA). Some circuits bake params into the VK.
    pub params_path: Option<PathBuf>,
}

/// A "drop-in" verifier that implements the gateway's `ZkVerifier` trait.
///
/// This crate is deliberately structured so you can:
/// - keep the gateway generic
/// - swap in a real Halo2 verifier without touching request routing / nullifier DB / etc.
///
/// By default, this verifier is compiled *without* pulling in halo2 dependencies.
/// To enable real verification, build with the `halo2` feature.
#[cfg(feature = "halo2")]
pub struct Halo2PlonkVerifier {
    vk_bytes: Vec<u8>,
    params_bytes: Option<Vec<u8>>,
}

#[cfg(not(feature = "halo2"))]
pub struct Halo2PlonkVerifier;

impl Halo2PlonkVerifier {
    /// Create a verifier from on-disk artifacts.
    pub fn new(cfg: Halo2PlonkVerifierConfig) -> Result<Self> {
        // Fail fast if the crate wasn't compiled with halo2 support.
        #[cfg(not(feature = "halo2"))]
        {
            let _ = cfg;
            anyhow::bail!(
                "Halo2 verifier not enabled in this build. Recompile with --features halo2"
            );
        }

        #[cfg(feature = "halo2")]
        {
            let vk_bytes = std::fs::read(&cfg.verifying_key_path).with_context(|| {
                format!("read verifying key {}", cfg.verifying_key_path.display())
            })?;
            let params_bytes = match &cfg.params_path {
                Some(p) => {
                    Some(std::fs::read(p).with_context(|| format!("read params {}", p.display()))?)
                }
                None => None,
            };

            Ok(Self {
                vk_bytes,
                params_bytes,
            })
        }
    }

    #[cfg(feature = "halo2")]
    fn verify_halo2_proof(&self, ticket: &ZkTicket) -> std::result::Result<(), ZkVerifyError> {
        // IMPORTANT: This is intentionally a *skeleton*.
        //
        // In a real implementation, you would:
        // 1) Deserialize vk/params into the halo2_proofs types for your chosen commitment scheme
        // 2) Convert public inputs into field elements in the exact order expected by your circuit
        // 3) Call `halo2_proofs::plonk::verify_proof` with the correct transcript and scheme
        //
        // What should be public inputs?
        // - commitment_root
        // - nullifier
        // - token_class id
        // ...and optionally a domain separator to bind the proof to THIS gateway/provider.
        //
        // Because circuits differ, this repository does not ship a one-size-fits-all verifier.
        // The *interface* is here so you can plug yours in cleanly.

        let _ = ticket;
        let _ = (&self.vk_bytes, &self.params_bytes);
        Err(ZkVerifyError::Internal(
            "halo2 proof verification is not implemented; refusing to accept tickets".to_string(),
        ))
    }
}

impl ZkVerifier for Halo2PlonkVerifier {
    fn verify(&self, ticket: &ZkTicket) -> std::result::Result<VerifiedTicket, ZkVerifyError> {
        #[cfg(feature = "halo2")]
        {
            self.verify_halo2_proof(ticket)?;
            return Ok(VerifiedTicket {
                token_class: ticket.token_class,
                nullifier_key: replay_key(ticket),
            });
        }

        #[cfg(not(feature = "halo2"))]
        {
            let _ = ticket;
            Err(ZkVerifyError::Internal(
                "halo2 verifier not enabled in this build".to_string(),
            ))
        }
    }
}
