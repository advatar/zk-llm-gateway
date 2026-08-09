use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use zk_llm_common::{
    token::TokenClass,
    zk::{sha256, VerificationContext, VerifiedTicket, ZkTicket, ZkVerifier, ZkVerifyError},
};

const MAX_ACTUM_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct ActumVerifier {
    client: Client,
    endpoint: Url,
    bearer_token: String,
    audience: String,
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    protocol: &'static str,
    audience: &'a str,
    request_commitment_b64: String,
    replay_identifier_b64: String,
    token_class: TokenClass,
    payment_evidence_b64: String,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    authorized: bool,
    finalized: bool,
    request_commitment_b64: String,
    authorization_id_b64: String,
    token_class: TokenClass,
}

impl ActumVerifier {
    pub fn new(
        endpoint: &str,
        bearer_token: String,
        audience: String,
        timeout: Duration,
        allow_insecure_http: bool,
    ) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        if endpoint.scheme() != "https" && !allow_insecure_http {
            anyhow::bail!("ACTUM_VERIFIER_URL must use https outside local development");
        }
        if bearer_token.is_empty() {
            anyhow::bail!("ACTUM_VERIFIER_BEARER_TOKEN is required");
        }
        if audience.is_empty() {
            anyhow::bail!("ACTUM_AUDIENCE is required");
        }
        let client = Client::builder().timeout(timeout).build()?;
        Ok(Self {
            client,
            endpoint,
            bearer_token,
            audience,
        })
    }
}

#[async_trait]
impl ZkVerifier for ActumVerifier {
    async fn verify(
        &self,
        ticket: &ZkTicket,
        context: &VerificationContext,
    ) -> Result<VerifiedTicket, ZkVerifyError> {
        if context.request_commitment.len() != 48
            || ticket.commitment_root.0 != context.request_commitment
            || ticket.nullifier.0.is_empty()
            || ticket.proof.0.is_empty()
            || ticket.proof.0.len() > MAX_ACTUM_EVIDENCE_BYTES
        {
            return Err(ZkVerifyError::InvalidProof);
        }

        let request = VerifyRequest {
            protocol: "actum.payment-finality.v1",
            audience: &self.audience,
            request_commitment_b64: B64.encode(&context.request_commitment),
            replay_identifier_b64: B64.encode(&ticket.nullifier.0),
            token_class: ticket.token_class,
            payment_evidence_b64: B64.encode(&ticket.proof.0),
        };
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.bearer_token)
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                ZkVerifyError::Internal(format!("Actum verifier unavailable: {error}"))
            })?;

        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY
        {
            return Err(ZkVerifyError::InvalidProof);
        }
        if !response.status().is_success() {
            return Err(ZkVerifyError::Internal(format!(
                "Actum verifier returned {}",
                response.status()
            )));
        }
        let response: VerifyResponse = response.json().await.map_err(|error| {
            ZkVerifyError::Internal(format!("malformed Actum response: {error}"))
        })?;
        let echoed_commitment = B64
            .decode(response.request_commitment_b64)
            .map_err(|_| ZkVerifyError::InvalidProof)?;
        let authorization_id = B64
            .decode(response.authorization_id_b64)
            .map_err(|_| ZkVerifyError::InvalidProof)?;
        if !response.authorized
            || !response.finalized
            || response.token_class != ticket.token_class
            || echoed_commitment != context.request_commitment
            || authorization_id.is_empty()
        {
            return Err(ZkVerifyError::InvalidProof);
        }

        Ok(VerifiedTicket {
            token_class: response.token_class,
            nullifier_key: sha256(&authorization_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use zk_llm_common::zk::B64Bytes;

    async fn verifier_handler(
        State(expected): State<Arc<Vec<u8>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "authorized": true,
            "finalized": true,
            "request_commitment_b64": body["request_commitment_b64"],
            "authorization_id_b64": B64.encode(expected.as_slice()),
            "token_class": body["token_class"],
        }))
    }

    async fn test_verifier() -> (ActumVerifier, Vec<u8>) {
        let authorization_id = vec![42; 48];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/verify", post(verifier_handler))
            .with_state(Arc::new(authorization_id.clone()));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let verifier = ActumVerifier::new(
            &format!("http://{address}/v1/verify"),
            "test-secret".into(),
            "zerok:test".into(),
            Duration::from_secs(1),
            true,
        )
        .unwrap();
        (verifier, authorization_id)
    }

    fn ticket(commitment: Vec<u8>) -> ZkTicket {
        ZkTicket {
            commitment_root: B64Bytes(commitment),
            nullifier: B64Bytes(vec![7; 48]),
            token_class: TokenClass::C512,
            proof: B64Bytes(vec![9; 128]),
        }
    }

    #[tokio::test]
    async fn accepts_finalized_bound_authorization() {
        let (verifier, authorization_id) = test_verifier().await;
        let commitment = vec![3; 48];
        let verified = verifier
            .verify(
                &ticket(commitment.clone()),
                &VerificationContext {
                    request_commitment: commitment,
                },
            )
            .await
            .unwrap();
        assert_eq!(verified.nullifier_key, sha256(&authorization_id));
        assert_eq!(verified.token_class, TokenClass::C512);
    }

    #[tokio::test]
    async fn rejects_request_commitment_substitution_before_network_call() {
        let (verifier, _) = test_verifier().await;
        let error = verifier
            .verify(
                &ticket(vec![3; 48]),
                &VerificationContext {
                    request_commitment: vec![4; 48],
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ZkVerifyError::InvalidProof));
    }

    #[test]
    fn rejects_plain_http_without_explicit_local_override() {
        assert!(ActumVerifier::new(
            "http://127.0.0.1:9999/v1/verify",
            "test-secret".into(),
            "zerok:test".into(),
            Duration::from_secs(1),
            false,
        )
        .is_err());
    }

    #[tokio::test]
    async fn verifier_unavailability_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let verifier = ActumVerifier::new(
            &format!("http://{address}/v1/verify"),
            "test-secret".into(),
            "zerok:test".into(),
            Duration::from_millis(100),
            true,
        )
        .unwrap();
        let commitment = vec![3; 48];
        let error = verifier
            .verify(
                &ticket(commitment.clone()),
                &VerificationContext {
                    request_commitment: commitment,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ZkVerifyError::Internal(_)));
    }
}
