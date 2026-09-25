//! Local-development-only qualification, using real common crypto and dev tickets.
//! This never supplies production finality evidence or calls a compatibility fallback.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::Client;
use serde_json::{json, Value};
use std::{collections::HashMap, time::Duration};
use uuid::Uuid;
use zk_llm_common::{
    envelope::{seal_request_for_gateway, Envelope},
    token::TokenClass,
    types::{ChatMessage, GatewayEnvelopePayload, InferenceRequest},
    zk::{B64Bytes, ZkTicket},
};
// Reuse the CLI's development evidence construction; other ticket sources are
// intentionally unused by this local-only example.
#[allow(dead_code)]
#[path = "../src/tickets.rs"]
mod tickets;
use tickets::{ActumDevTicketSource, TicketSource};

fn local_url(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    let url = reqwest::Url::parse(&value)?;
    ensure!(
        matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        "local qualification requires loopback URLs"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "credentials in URL refused"
    );
    Ok(value.trim_end_matches('/').to_owned())
}

fn request() -> Result<InferenceRequest> {
    let mut req = InferenceRequest {
        request_id: Uuid::new_v4(),
        model: "vir-mock-llm".into(),
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "Synthetic paid qualification".into(),
            extra: HashMap::new(),
        }],
        max_tokens: None,
        temperature: None,
        stream: None,
        token_class: TokenClass::C2048,
        ticket: ZkTicket {
            commitment_root: B64Bytes(vec![]),
            nullifier: B64Bytes(vec![]),
            token_class: TokenClass::C2048,
            proof: B64Bytes(vec![]),
        },
        provider_options: HashMap::new(),
    };
    req.ticket =
        ActumDevTicketSource.next_ticket(req.token_class, &req.authorization_commitment()?)?;
    Ok(req)
}

async fn send(
    client: &Client,
    base: &str,
    key: [u8; 32],
    req: &InferenceRequest,
) -> Result<GatewayEnvelopePayload> {
    let (envelope, context) = seal_request_for_gateway(
        key,
        req.token_class,
        req.request_id,
        &serde_json::to_vec(req)?,
    )?;
    let response = client
        .post(format!("{base}/v1/infer"))
        .json(&envelope)
        .send()
        .await?
        .error_for_status()?;
    let response: Envelope = response.json().await?;
    let payload: GatewayEnvelopePayload =
        serde_json::from_slice(&context.open_response(&response)?)?;
    match &payload {
        GatewayEnvelopePayload::Ok { response } => ensure!(
            response.request_id == req.request_id,
            "response request binding"
        ),
        GatewayEnvelopePayload::Err { error } => ensure!(
            error.request_id == Some(req.request_id),
            "error request binding"
        ),
    }
    Ok(payload)
}

fn refused(payload: GatewayEnvelopePayload, code: &str) -> Result<()> {
    match payload {
        GatewayEnvelopePayload::Err { error } => {
            ensure!(error.code == code, "expected {code}, got {}", error.code)
        }
        GatewayEnvelopePayload::Ok { .. } => bail!("unauthorized request executed"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let base = local_url("LOCAL_GATEWAY_URL")?;
    let vir = local_url("LOCAL_VIR_URL")?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let public: Value = client
        .get(format!("{base}/v1/pubkey"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let key: [u8; 32] = B64
        .decode(
            public["public_key_b64"]
                .as_str()
                .context("public key missing")?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key length"))?;
    let req = request()?;
    if std::env::var("LOCAL_EXPECT_VERIFIER_UNAVAILABLE").as_deref() == Ok("true") {
        refused(send(&client, &base, key, &req).await?, "internal_error")?;
        println!("PASS unavailable verifier fails closed with encrypted error");
        return Ok(());
    }

    let response = match send(&client, &base, key, &req).await? {
        GatewayEnvelopePayload::Ok { response } => response,
        GatewayEnvelopePayload::Err { error } => bail!("paid request refused: {}", error.code),
    };
    ensure!(!response.output.is_empty(), "empty inference output");
    let upstream = response.upstream.context("VIR upstream response missing")?;
    let receipt = upstream["verification"]["receipt_id"]
        .as_str()
        .context("VIR receipt id missing")?;
    let verification: Value = client
        .post(format!("{vir}/v1/receipts/{receipt}/verify"))
        .bearer_auth(std::env::var("LOCAL_VIR_API_KEY")?)
        .json(&json!({}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        verification["valid"] == true,
        "VIR receipt verification failed"
    );
    println!("PASS encrypted paid inference / request-response binding / local Actum / VIR receipt verification");
    // Re-encrypt the same payload: same authorization and replay identity, fresh envelope.
    refused(send(&client, &base, key, &req).await?, "double_spend")?;
    println!("PASS second-use replay refused (same authorization identity)");
    let actum = local_url("LOCAL_ACTUM_URL")?;
    let wrong_audience = client.post(format!("{actum}/v1/verify-inference-authorization"))
        .bearer_auth(std::env::var("ACTUM_VERIFIER_BEARER_TOKEN")?)
        .json(&json!({"protocol":"actum.payment-finality.v1", "audience":"deliberately-wrong-local-audience",
            "request_commitment_b64": B64.encode(&req.ticket.commitment_root.0),
            "replay_identifier_b64": B64.encode(&req.ticket.nullifier.0),
            "token_class":req.token_class, "payment_evidence_b64":B64.encode(&req.ticket.proof.0)}))
        .send().await?;
    ensure!(
        wrong_audience.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY
            || wrong_audience.status() == reqwest::StatusCode::FORBIDDEN,
        "wrong audience not refused"
    );
    println!("PASS wrong audience refused by local Actum fixture");
    let mut missing = request()?;
    missing.ticket.proof.0.clear();
    let mut malformed = request()?;
    malformed.ticket.proof.0 = b"not-json".to_vec();
    let mut substituted = request()?;
    substituted.messages[0].content.push_str(" substituted");
    let mut wrong_class = request()?;
    wrong_class.ticket.token_class = TokenClass::C512;
    let mut nonfinal = request()?;
    let mut evidence: Value = serde_json::from_slice(&nonfinal.ticket.proof.0)?;
    evidence["finalized"] = json!(false);
    nonfinal.ticket.proof.0 = serde_json::to_vec(&evidence)?;
    for (name, req, code) in [
        ("missing evidence", missing, "invalid_proof"),
        ("malformed evidence", malformed, "invalid_proof"),
        ("request substitution", substituted, "invalid_proof"),
        ("wrong class", wrong_class, "token_class_mismatch"),
        ("nonfinal evidence", nonfinal, "invalid_proof"),
    ] {
        refused(send(&client, &base, key, &req).await?, code)?;
        println!("PASS {name} refused");
    }
    Ok(())
}
