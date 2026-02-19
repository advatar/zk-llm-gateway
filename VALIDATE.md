# Validation

## Automated (completed)

- `cargo fmt`
- `cargo test -p zk_llm_common`
- `cargo test -p zk_llm_gateway`
- `cargo test -p zk_llm_relay`
- `cargo test -p zk_llm_client`

## Manual checks (for user)

1. Start gateway with dev verifier:

```bash
export GATEWAY_SECRET_KEY_B64="..."
export GATEWAY_ALLOW_DUMMY_VERIFIER=true
cargo run -p zk_llm_gateway
```

2. Verify public key endpoint:

```bash
curl -sS http://127.0.0.1:8080/v1/pubkey
```

Expected JSON shape:

```json
{"public_key_b64":"..."}
```

3. Verify relay accepts SDK envelope field names (`v`, `eph_pubkey_b64`) and forwards to gateway.

4. Validate SDK roundtrip from `../zk-llm-gateway-rust-sdk`:

```bash
cd ../zk-llm-gateway-rust-sdk
GATEWAY_URL=http://127.0.0.1:8080 cargo run --example basic_chat
```

If using relay:

```bash
GATEWAY_URL=http://127.0.0.1:8081/relay cargo run --example basic_chat
```
