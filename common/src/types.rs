use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
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
