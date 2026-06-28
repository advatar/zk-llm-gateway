# ZK LLM Gateway (Rust)

This is a Rust workspace that scaffolds a **privacy-preserving API gateway** for LLM inference,
with a client designed for the **long-running personal agent** use case.

It implements the *plumbing* needed for a "ZK API usage credits"-style system:

- **Encrypted envelopes** for relay-friendly transport (relay can't read prompts)
- **Token-class quantization** + **padding** to reduce metadata leakage
- **Replay protection** (nullifier DB)
- A pluggable **ZK verifier trait** (dummy verifier in dev)
- A **privacy relay** that forwards encrypted envelopes without leaking client IP to the gateway
- A **personal-agent client** that keeps conversation state *locally* and minimizes/redacts context sent to the remote model
  - Interactive **REPL** mode for long chats
  - Optional **local HTTP API** for GUI integrations
  - Local **session file** (optional encryption at rest)
  - Local **memory items** (selectively revealed)
  - Local **RAG-style retrieval** (BM25-ish) to recall only relevant memory/snippets
  - Local **rolling summary** (optionally updated by a local summarizer model)
  - A **prompt packer** that fits context into token-class budgets
  - A **redaction engine** that replaces sensitive strings with reversible placeholders

> ⚠️ This is an MVP scaffolding. The repo ships a **dummy verifier** (dev only) and a **Halo2 verifier skeleton**
> (circuit-specific) behind a feature flag.

---

## Repository layout

- `common/` — shared types (envelopes, token classes, request/response structs, ZK ticket types)
- `gateway/` — the LLM gateway (decrypts envelope, verifies ticket, checks replay, forwards to provider)
- `relay/` — optional privacy relay (forwards encrypted envelopes; gateway sees relay IP, not client IP)
- `client/` — CLI that stores history locally and sends only minimized context
- `zk-llm-gateway-*-sdk/` — language SDKs tracked as Git submodules

---

## SDK submodules

Client SDK repositories:

- [Rust SDK](https://github.com/advatar/zk-llm-gateway-rust-sdk)
- [Python SDK](https://github.com/advatar/zk-llm-gateway-python-sdk)
- [TypeScript SDK](https://github.com/advatar/zk-llm-gateway-typescript-sdk)
- [Swift SDK](https://github.com/advatar/zk-llm-gateway-swift-sdk)

Initialize SDK repos after cloning:

```bash
git submodule update --init --recursive
```

Each SDK stays versioned in its own repository while this repo pins the SDK commits that match the gateway wire format.

---

## Threat model + privacy notes

This system is designed to address several different "linkability" layers:

1. **Payment/authorization unlinkability** (goal)
   - Achieved by a real ZK verifier binding a ticket to a deposit/commitment, without revealing identity.
   - This repo includes the data model + verifier trait, but not a real circuit yet.

2. **Transport unlinkability** (partial)
   - If you use the `relay`, the **gateway does not see the client IP**.
   - Envelopes are encrypted end-to-end, so the relay can't read prompts.

3. **Metadata shaping** (partial)
   - Requests use discrete `TokenClass` buckets and fixed-size padding before encryption.
   - This reduces ciphertext length and coarsens billing metadata.

4. **Content/context linkability** (client-side)
   - The client stores long-term conversation history locally.
   - The client sends only recent messages + a compact, selectively-revealed memory/summary block.

What this does **not** solve by itself:
- The *LLM provider* can still cluster requests by **prompt content** (if you send unique personal context).
- The provider can also use inference **timing/token-count side channels**.
- If the relay and gateway collude, transport privacy is reduced.

---

## Quickstart (local dev)

### 1) Generate gateway keys

```bash
cargo run -p zk_llm_gateway -- --generate-keys
```

Export the secret key:

```bash
export GATEWAY_SECRET_KEY_B64="..."
```

Keep the public key for the client:

```bash
export GATEWAY_PUBLIC_KEY_B64="..."
```

### 2) Run an OpenAI-compatible provider

Point the gateway to any OpenAI-compatible endpoint (local `vllm`, `llama.cpp` server, etc.).
For example:

```bash
export PROVIDER_BASE_URL="http://127.0.0.1:8000"
# export PROVIDER_API_KEY="..."   # if required
```

### 3) Run the gateway (dev mode)

```bash
export GATEWAY_ALLOW_DUMMY_VERIFIER=true
cargo run -p zk_llm_gateway -- --zk-verifier dummy --listen-addr 127.0.0.1:8080
```

Dummy verification is dev-only and the gateway refuses to bind a non-loopback address while it is active.

Halo2/Plonk skeleton (circuit-specific):

```bash
export HALO2_VK_PATH="./path/to/verifying.key"
# export HALO2_PARAMS_PATH="./path/to/params"   # optional

# Build with the halo2 feature, then run with halo2 verifier selected
cargo run -p zk_llm_gateway --features halo2 -- --zk-verifier halo2
```

Gateway endpoints:

- `GET  /healthz`
- `GET  /v1/pubkey` (returns `{"public_key_b64":"..."}`)
- `POST /v1/infer` (encrypted envelope endpoint)
- `POST /v1/chat/completions` (OpenAI-compatible pass-through)
- `GET  /v1/models` (OpenAI-compatible pass-through)

### 4) Run the relay (optional but recommended)

```bash
cargo run -p zk_llm_relay
```

### 5) Run the personal-agent client

```bash
cargo run -p zk_llm_client -- \
  --gateway-public-key-b64 "$GATEWAY_PUBLIC_KEY_B64" \
  --endpoint-url "http://127.0.0.1:8081/relay" \
  --model "gpt-4o-mini" \
  --token-class c2048 \
  --session-file "./sessions/demo.session.json" \
  --system "You are a helpful assistant." \
  --use-dummy-tickets \
  --repl

```

The client requires a real ticket file by default. The `--use-dummy-tickets` flag is only for the local dummy-verifier quickstart; production clients should pass `--ticket-file ./tickets.json` instead.

Inside the REPL you can type messages normally, and also use:

- `/remember <text>` to store a private memory item
- `/memory` to list stored memory
- `/search <query>` to search memory + older messages locally
- `/redact <term>` to add a custom redaction term
- `/exit` to quit

### 6) (Optional) Run the client as a local HTTP API (for GUIs)

```bash
cargo run -p zk_llm_client -- \
  --gateway-public-key-b64 "$GATEWAY_PUBLIC_KEY_B64" \
  --endpoint-url "http://127.0.0.1:8081/relay" \
  --model "gpt-4o-mini" \
  --token-class c2048 \
  --session-file "./sessions/demo.session.json" \
  --use-dummy-tickets \
  --http-listen-addr 127.0.0.1:8090
```

If you want basic protection (recommended), set an API key:

```bash
export CLIENT_HTTP_API_KEY="change-me"
```

Endpoints:

Health
- `GET  /healthz`

Multi-session (recommended)
- `GET  /v1/sessions`
- `POST /v1/sessions` `{"session_id": "optional", "system": "optional"}`
- `GET  /v1/sessions/{session_id}`
- `GET  /v1/sessions/{session_id}/messages?limit=50`
- `POST /v1/sessions/{session_id}/chat` `{"message": "..."}`
- `POST /v1/sessions/{session_id}/chat/stream` (SSE; emits `start`, `delta`, `done`, `error`)
- `GET  /v1/sessions/{session_id}/memory`
- `POST /v1/sessions/{session_id}/memory` `{"text": "...", "tags": ["..."]}`
- `POST /v1/sessions/{session_id}/memory/search` `{"query": "...", "k": 8}`
- `POST /v1/sessions/{session_id}/redaction/term` `{"term": "..."}`
- `POST /v1/sessions/{session_id}/system` `{"system": "..."}`
- `POST /v1/sessions/{session_id}/save`

Legacy single-session (uses the default session id)
- `GET  /v1/session`
- `GET  /v1/messages?limit=50`
- `POST /v1/chat` `{"message": "..."}`
- `POST /v1/chat/stream` (SSE)
- `GET  /v1/memory`
- `POST /v1/memory` `{"text": "...", "tags": ["..."]}`
- `POST /v1/memory/search` `{"query": "...", "k": 8}`
- `POST /v1/redaction/term` `{"term": "..."}`
- `POST /v1/system` `{"system": "..."}`
- `POST /v1/save`

Streaming example:

```bash
curl -N \
  -H "Content-Type: application/json" \
  -H "x-api-key: $CLIENT_HTTP_API_KEY" \
  -d '{"message":"Hello"}' \
  http://127.0.0.1:8090/v1/chat/stream
```

Note: `/chat/stream` is **simulated streaming** (the gateway returns a full response, then the client emits it in fixed-size chunks for UI friendliness).

Optional: encrypt the session file at rest:

```bash
export SESSION_KEY_B64="<base64-32-bytes>"
```

Optional: use a local summarizer (OpenAI-compatible) on localhost:

```bash
export LOCAL_SUMMARIZER_URL="http://127.0.0.1:8001"
export LOCAL_SUMMARIZER_MODEL="llama-3.1-8b"
```


---

## Next steps (to make this real)

1. Implement a real ZK verifier (Halo2 / Plonk / Groth16) for `ZkTicket`
2. Connect deposits + slashing to an onchain contract
3. Add better **local summarization** / **RAG** in the client (local model)
4. Add padding strategies for inference metadata (token budget classes, optional minimum response times)
5. Consider TEEs/confidential inference if you want to reduce trust in gateway/provider infrastructure
