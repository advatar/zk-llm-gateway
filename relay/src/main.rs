use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use log::{info, warn};
use serde_json::{json, Value};
use tokio::time::timeout;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use zk_llm_common::envelope::Envelope;

#[derive(Parser, Debug)]
#[command(name = "zk-llm-relay")]
struct Cli {
    #[arg(long, env = "RELAY_LISTEN_ADDR", default_value = "0.0.0.0:8081")]
    listen_addr: String,

    /// Gateway URL (e.g. http://gateway:8080/v1/infer)
    #[arg(
        long,
        env = "RELAY_GATEWAY_URL",
        default_value = "http://127.0.0.1:8080/v1/infer"
    )]
    gateway_url: String,

    /// Timeout (ms) for forwarding requests to gateway
    #[arg(long, env = "RELAY_TIMEOUT_MS", default_value_t = 120_000)]
    timeout_ms: u64,

    /// Comma-separated browser origins allowed to call the relay.
    #[arg(
        long,
        env = "RELAY_CORS_ALLOWED_ORIGINS",
        default_value = "http://localhost:3000,http://127.0.0.1:3000"
    )]
    cors_allowed_origins: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(cli.timeout_ms))
        .build()
        .context("failed to build reqwest client")?;

    let state = Arc::new(RelayState {
        gateway_url: cli.gateway_url,
        timeout_ms: cli.timeout_ms,
        http,
    });

    let cors = cors_layer(&cli.cors_allowed_origins)?;

    let app = Router::new()
        .route("/", get(docs))
        .route("/docs", get(docs))
        .route("/openapi.json", get(openapi_json))
        .route("/healthz", get(healthz))
        .route("/relay", post(relay))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cli
        .listen_addr
        .parse()
        .context("invalid RELAY_LISTEN_ADDR")?;

    info!("relay listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind")?;

    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

fn cors_layer(allowed_origins: &str) -> Result<CorsLayer> {
    let origins = allowed_origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .with_context(|| format!("invalid CORS origin: {}", origin))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION]))
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ZK LLM Relay API</title>
  <style>
    body {
      margin: 0;
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      line-height: 1.5;
    }
    main {
      max-width: 860px;
      margin: 0 auto;
      padding: 36px 20px 56px;
    }
    h1 { margin: 0 0 8px; font-size: 30px; }
    h2 { margin-top: 28px; font-size: 20px; }
    .hint { color: #93c5fd; }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
      background: #111827;
      border: 1px solid #334155;
      border-radius: 8px;
    }
    code { padding: 2px 6px; }
    pre {
      margin: 10px 0 0;
      padding: 12px;
      overflow-x: auto;
      color: #d1fae5;
    }
    a { color: #93c5fd; text-decoration: none; }
    a:hover { text-decoration: underline; }
    ul { padding-left: 20px; }
  </style>
</head>
<body>
  <main>
    <h1>ZK LLM Relay API</h1>
    <p class="hint">Privacy relay for encrypted gateway envelopes.</p>

    <h2>Endpoints</h2>
    <ul>
      <li><code>GET /healthz</code> - Liveness check</li>
      <li><code>POST /relay</code> - Forward encrypted envelope to gateway</li>
      <li><code>GET /docs</code> - This page</li>
      <li><code>GET /openapi.json</code> - OpenAPI document</li>
    </ul>

    <h2>Health Check</h2>
    <pre>curl -sS https://proxy.zerok.cloud/healthz</pre>

    <h2>Relay Request</h2>
    <p>Submit a JSON <code>Envelope</code> payload from the client.</p>
    <pre>curl -sS https://proxy.zerok.cloud/relay \
  -H "content-type: application/json" \
  -d '{"v":2,"token_class":"c256","request_id":"...","client_nonce_b64":"...","eph_pubkey_b64":"...","nonce_b64":"...","ciphertext_b64":"..."}'</pre>

    <h2>Notes</h2>
    <ul>
      <li>The relay cannot decrypt payload contents.</li>
      <li>The client needs <code>GATEWAY_PUBLIC_KEY_B64</code> from the gateway operator.</li>
      <li>Machine-readable spec: <a href="/openapi.json">/openapi.json</a></li>
      <li>See the workspace README for full setup and client usage details.</li>
    </ul>
  </main>
</body>
</html>"#,
    )
}

async fn openapi_json() -> Json<Value> {
    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "ZK LLM Relay API",
            "version": "1.0.0",
            "description": "Privacy relay for forwarding encrypted envelope payloads to the gateway."
        },
        "servers": [
            {
                "url": "https://proxy.zerok.cloud"
            }
        ],
        "paths": {
            "/healthz": {
                "get": {
                    "summary": "Health check",
                    "operationId": "healthz",
                    "responses": {
                        "200": {
                            "description": "Relay is healthy",
                            "content": {
                                "text/plain": {
                                    "schema": {
                                        "type": "string",
                                        "example": "ok"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/relay": {
                "post": {
                    "summary": "Forward encrypted envelope",
                    "operationId": "relayEnvelope",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/Envelope"
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Encrypted envelope response from gateway",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Envelope"
                                    }
                                }
                            }
                        },
                        "502": {
                            "description": "Gateway unreachable or returned error",
                            "content": {
                                "text/plain": {
                                    "schema": {
                                        "type": "string",
                                        "examples": {
                                            "gateway_unreachable": {
                                                "value": "gateway unreachable"
                                            },
                                            "gateway_error": {
                                                "value": "gateway error"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "504": {
                            "description": "Gateway timeout",
                            "content": {
                                "text/plain": {
                                    "schema": {
                                        "type": "string",
                                        "example": "gateway timeout"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "TokenClass": {
                    "type": "string",
                    "enum": ["c256", "c512", "c1024", "c2048", "c4096"]
                },
                "Envelope": {
                    "type": "object",
                    "required": ["v", "token_class", "request_id", "client_nonce_b64", "eph_pubkey_b64", "nonce_b64", "ciphertext_b64"],
                    "properties": {
                        "v": {
                            "type": "integer",
                            "minimum": 2,
                            "example": 2
                        },
                        "token_class": {
                            "$ref": "#/components/schemas/TokenClass"
                        },
                        "request_id": {
                            "type": "string",
                            "format": "uuid",
                            "description": "Client-generated request id authenticated into the envelope transcript"
                        },
                        "client_nonce_b64": {
                            "type": "string",
                            "description": "Base64-encoded 32-byte client nonce"
                        },
                        "eph_pubkey_b64": {
                            "type": "string",
                            "description": "Base64-encoded client ephemeral public key"
                        },
                        "nonce_b64": {
                            "type": "string",
                            "description": "Base64-encoded AEAD nonce"
                        },
                        "ciphertext_b64": {
                            "type": "string",
                            "description": "Base64-encoded encrypted payload"
                        }
                    }
                }
            }
        }
    }))
}

struct RelayState {
    gateway_url: String,
    timeout_ms: u64,
    http: reqwest::Client,
}

async fn relay(
    State(state): State<Arc<RelayState>>,
    Json(env): Json<Envelope>,
) -> Result<Json<Envelope>, RelayError> {
    // Privacy note:
    // - We do NOT add X-Forwarded-For headers.
    // - We do NOT log request bodies.

    let fwd = state.http.post(&state.gateway_url).json(&env).send();

    let resp = timeout(Duration::from_millis(state.timeout_ms), fwd)
        .await
        .map_err(|_| RelayError::gateway_timeout())
        .and_then(|r| r.map_err(|_| RelayError::gateway_unreachable()))?;

    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| RelayError::gateway_unreachable())?;

    if !status.is_success() {
        warn!(
            "gateway returned non-success status={} body_len={}",
            status,
            bytes.len()
        );
        return Err(RelayError::gateway_error());
    }

    let out: Envelope = serde_json::from_slice(&bytes).map_err(|_| RelayError::gateway_error())?;
    Ok(Json(out))
}

#[derive(Debug, thiserror::Error)]
enum RelayError {
    #[error("gateway timeout")]
    Timeout,
    #[error("gateway unreachable")]
    Unreachable,
    #[error("gateway error")]
    GatewayError,
}

impl RelayError {
    fn gateway_timeout() -> Self {
        RelayError::Timeout
    }
    fn gateway_unreachable() -> Self {
        RelayError::Unreachable
    }
    fn gateway_error() -> Self {
        RelayError::GatewayError
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            RelayError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "gateway timeout"),
            RelayError::Unreachable => (StatusCode::BAD_GATEWAY, "gateway unreachable"),
            RelayError::GatewayError => (StatusCode::BAD_GATEWAY, "gateway error"),
        };
        (status, msg).into_response()
    }
}
