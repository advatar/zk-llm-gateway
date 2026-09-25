//! Bounded input and upstream-response checks for the production HTTP path.
//! These checks do not mint authority, attest a model, or replace Actum verification.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use zk_llm_common::{envelope::Envelope, types::InferenceRequest};

pub(super) fn check_envelope_size(env: &Envelope) -> Result<(), &'static str> {
    if env.version != Envelope::VERSION {
        return Err("unsupported_envelope_version");
    }
    let expected = env.token_class.envelope_request_plaintext_bytes() + 16;
    // Bound decoding too. The HTTP layer separately caps the entire JSON body.
    if env.ciphertext_b64.len() != ((expected + 2) / 3) * 4 {
        return Err("envelope_size_mismatch");
    }
    let ciphertext = B64.decode(&env.ciphertext_b64).map_err(|_| "invalid_ciphertext")?;
    if ciphertext.len() != expected {
        return Err("envelope_size_mismatch");
    }
    Ok(())
}

pub(super) fn check_request(env: &Envelope, req: &InferenceRequest) -> Result<(), &'static str> {
    if req.request_id != env.request_id {
        return Err("request_id_mismatch");
    }
    if req.model.trim().is_empty() || req.messages.is_empty() {
        return Err("invalid_request");
    }
    // Reject conflicting structural fields and alternate output-budget knobs.
    // This is intentionally not a claim to validate every provider-specific option.
    const RESERVED: &[&str] = &[
        "request_id", "model", "messages", "max_tokens", "temperature", "stream",
        "token_class", "ticket", "provider_options", "max_completion_tokens",
        "max_output_tokens", "api_key", "authorization",
    ];
    if RESERVED.iter().any(|key| req.provider_options.contains_key(*key)) {
        return Err("reserved_provider_option");
    }
    if req.provider_options.get("n").is_some_and(|value| value.as_u64() != Some(1)) {
        return Err("multiple_completions_unsupported");
    }
    if req.provider_options.get("store").is_some_and(|value| value.as_bool() != Some(false)) {
        return Err("provider_storage_unsupported");
    }
    // Also protect typed/internal callers: message.extra is a flattened map.
    if req.messages.iter().any(|message| {
        message.extra.contains_key("role") || message.extra.contains_key("content")
    }) {
        return Err("reserved_message_field");
    }
    Ok(())
}

pub(super) async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, &'static str> {
    if response.headers().get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err("compressed_upstream_unsupported");
    }
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err("upstream_too_large");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "upstream_read")? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err("upstream_too_large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
