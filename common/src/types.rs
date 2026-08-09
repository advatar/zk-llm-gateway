use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::token::TokenClass;
use crate::zk::ZkTicket;

/// A minimal OpenAI-compatible chat message type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default, deserialize_with = "deserialize_chat_message_content")]
    pub content: String,
    #[serde(default, flatten)]
    pub extra: HashMap<String, Value>,
}

/// Request payload sent *inside* the encrypted envelope.
///
/// Privacy notes:
/// - The gateway should not persist this structure.
/// - The client should keep long-term memory locally and only send the
///   minimum context required for the task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Client-generated request id (useful for client-side correlation without
    /// relying on provider/gateway logs).
    pub request_id: Uuid,

    /// Model identifier (OpenAI-compatible) to route.
    pub model: String,

    /// Chat messages to send to the model.
    pub messages: Vec<ChatMessage>,

    /// Requested max completion tokens.
    ///
    /// For privacy, the gateway may ignore this and clamp to `token_class`.
    pub max_tokens: Option<u32>,

    /// Sampling temperature.
    pub temperature: Option<f32>,

    /// The canonical `/v1/infer` path is non-streaming today.
    ///
    /// Clients may send `false` (or omit the field). `true` is rejected so the
    /// request does not silently degrade into a non-streaming call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,

    /// The privacy/billing bucket for this request.
    pub token_class: TokenClass,

    /// Anonymous usage authorization.
    pub ticket: ZkTicket,

    /// Additional OpenAI-compatible request fields forwarded to the upstream
    /// provider. Examples include `top_p`, `response_format`, and `tools`.
    #[serde(default, flatten)]
    pub provider_options: HashMap<String, Value>,
}

impl InferenceRequest {
    /// Computes the stable, domain-separated commitment an authorization must bind to.
    ///
    /// The ticket is deliberately excluded to avoid a circular commitment. JSON objects are
    /// recursively sorted so HashMap iteration order cannot change the result across clients.
    pub fn authorization_commitment(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::json!({
            "request_id": self.request_id,
            "model": self.model,
            "messages": self.messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": self.stream,
            "token_class": self.token_class,
            "provider_options": self.provider_options,
        });
        canonicalize_json(&mut value);
        let encoded = serde_json::to_vec(&value)?;
        let mut hasher = Sha256::new();
        hasher.update(b"ZEROK-ACTUM-INFERENCE-AUTHORIZATION-V1\0");
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().to_vec())
    }
}

fn canonicalize_json(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = std::mem::take(object).into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (_, child) in &mut entries {
                canonicalize_json(child);
            }
            object.extend(entries);
        }
        Value::Array(values) => values.iter_mut().for_each(canonicalize_json),
        _ => {}
    }
}

/// Response payload returned *inside* the encrypted envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    pub request_id: Uuid,
    pub model: String,

    /// Assistant output text.
    pub output: String,

    /// Coarsened usage info (does not reveal exact token counts).
    pub billed_token_class: TokenClass,

    /// Raw upstream response body for OpenAI-compatible clients that need
    /// provider-specific fields such as tool calls or structured outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Value>,
}

/// A machine-readable error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub request_id: Option<Uuid>,
    pub code: String,
    pub message: String,
}

/// The plaintext payload that is encrypted inside gateway envelopes.
///
/// We use an enum so the gateway can return *encrypted errors* without leaking
/// error types or other details to a privacy relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatewayEnvelopePayload {
    Ok { response: InferenceResponse },
    Err { error: ErrorResponse },
}

fn deserialize_chat_message_content<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s),
        Some(other) => serde_json::to_string(&other).map_err(serde::de::Error::custom),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::{B64Bytes, ZkTicket};

    fn request(provider_options: HashMap<String, Value>) -> InferenceRequest {
        InferenceRequest {
            request_id: Uuid::nil(),
            model: "actum-test-model".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "hello".into(),
                extra: HashMap::new(),
            }],
            max_tokens: Some(128),
            temperature: Some(0.5),
            stream: None,
            token_class: TokenClass::C512,
            ticket: ZkTicket {
                commitment_root: B64Bytes(vec![]),
                nullifier: B64Bytes(vec![1]),
                token_class: TokenClass::C512,
                proof: B64Bytes(vec![2]),
            },
            provider_options,
        }
    }

    #[test]
    fn authorization_commitment_is_independent_of_map_insertion_order() {
        let first = HashMap::from([
            ("top_p".into(), Value::from(0.9)),
            ("seed".into(), Value::from(7)),
        ]);
        let second = HashMap::from([
            ("seed".into(), Value::from(7)),
            ("top_p".into(), Value::from(0.9)),
        ]);
        assert_eq!(
            request(first).authorization_commitment().unwrap(),
            request(second).authorization_commitment().unwrap()
        );
    }

    #[test]
    fn authorization_commitment_changes_with_billable_request() {
        let first = request(HashMap::new());
        let mut second = request(HashMap::new());
        second.model = "substituted-model".into();
        assert_ne!(
            first.authorization_commitment().unwrap(),
            second.authorization_commitment().unwrap()
        );
    }
}
