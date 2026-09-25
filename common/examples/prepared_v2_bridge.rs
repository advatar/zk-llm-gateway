//! Offline conformance bridge only. Never deploy as an inference/payment service.
//! Uses the actual common crate, rather than a second cryptographic implementation.
use std::io::{self, Read};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Deserialize;
use serde_json::Value;
use zk_llm_common::{
    envelope::{open_request_at_gateway, seal_response_at_gateway, Envelope, GatewayKeypair},
    types::{GatewayEnvelopePayload, InferenceRequest, InferenceResponse},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    gateway_secret_key_b64: String,
    envelope: Envelope,
    expected_request: Value,
    expected_commitment_b64: String,
}

fn main() -> Result<()> {
    const MAX_INPUT: usize = 2 * 1024 * 1024;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_INPUT {
        bail!("fixture too large");
    }
    let fixture: Fixture = serde_json::from_slice(&input).context("invalid fixture")?;
    let secret: [u8; 32] = B64
        .decode(&fixture.gateway_secret_key_b64)
        .context("invalid fixture key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid fixture key length"))?;
    let keys = GatewayKeypair::from_secret_bytes(secret);
    let ciphertext = B64.decode(&fixture.envelope.ciphertext_b64)?;
    if ciphertext.len() != fixture.envelope.token_class.envelope_request_plaintext_bytes() + 16 {
        bail!("request class size mismatch");
    }
    let plaintext = open_request_at_gateway(&keys, &fixture.envelope)?;
    let value: Value = serde_json::from_slice(&plaintext)?;
    if value != fixture.expected_request {
        bail!("request mismatch");
    }
    let request: InferenceRequest = serde_json::from_value(value)?;
    if request.request_id != fixture.envelope.request_id
        || request.token_class != fixture.envelope.token_class
        || request.ticket.token_class != request.token_class
    {
        bail!("request binding mismatch");
    }
    let commitment = request.authorization_commitment()?;
    if B64.encode(&commitment) != fixture.expected_commitment_b64
        || request.ticket.commitment_root.0 != commitment
    {
        bail!("commitment mismatch");
    }
    // No Actum call, finality verification, provider call or payment acceptance.
    let response = GatewayEnvelopePayload::Ok {
        response: InferenceResponse {
            request_id: request.request_id,
            model: request.model,
            output: "synthetic native conformance response".to_owned(),
            billed_token_class: request.token_class,
            upstream: None,
        },
    };
    let envelope = seal_response_at_gateway(
        &keys,
        &fixture.envelope,
        &serde_json::to_vec(&response)?,
    )?;
    println!("{}", serde_json::to_string(&envelope)?);
    Ok(())
}
