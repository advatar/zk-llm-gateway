use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::token::TokenClass;
use crate::zk::ZkTicket;

/// A minimal OpenAI-compatible chat message type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
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

    /// The privacy/billing bucket for this request.
    pub token_class: TokenClass,

    /// Anonymous usage authorization.
    pub ticket: ZkTicket,
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
