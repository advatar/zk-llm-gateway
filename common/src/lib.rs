//! Shared types for the ZK LLM Gateway workspace.
//!
//! The goal of this workspace is to make it easy to build a *privacy-preserving* API
//! gateway for LLM inference.
//!
//! Design choices that directly support privacy:
//! - **Request shaping** via token-class quantization and padding.
//! - **Relay-friendly** encrypted envelopes so a privacy relay can't read prompts.
//! - **ZK-verifier abstraction** so you can swap in a real proof system later.

pub mod envelope;
pub mod token;
pub mod types;
pub mod zk;
