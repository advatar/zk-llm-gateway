# Actum inference authorization verifier contract v1

`zk-llm-gateway` delegates production payment and finality semantics to Actum. The gateway does not
reinterpret ActiveChain canonical envelopes. It supplies the expected inference bindings to an
Actum-owned verifier endpoint and accepts only an exact, finalized result.

## Endpoint

`POST /v1/verify-inference-authorization`

Production transport must use TLS and an authenticated service credential. The gateway sends
`Authorization: Bearer <credential>` and `Content-Type: application/json`.

Request:

```json
{
  "protocol": "actum.payment-finality.v1",
  "audience": "actum:merchant:zerok-production",
  "request_commitment_b64": "<32 bytes>",
  "replay_identifier_b64": "<bounded non-empty bytes>",
  "token_class": "c2048",
  "payment_evidence_b64": "<canonical Actum evidence bundle>"
}
```

`payment_evidence_b64` is Actum-owned and should contain the canonical payment intent, finalized
settlement, finality bundle, and block receipt required by ActiveChain's verifier API. The Actum
implementation must:

1. Decode only supported canonical schema/type versions.
2. Verify the payment authorization and finality bundle against configured trusted genesis and
   verifier revisions.
3. Verify exact action inclusion using `verify_payment_finalized_settlement` or its normative
   successor.
4. Bind the payment intent's authorization/metadata context to `request_commitment_b64`, the
   merchant to `audience`, and the charged policy to `token_class`.
5. Bind `replay_identifier_b64` to the canonical intent, transaction, or private-cash nullifier.
6. Return success only for a non-refunded finalized payment eligible for this one inference.

Success response:

```json
{
  "authorized": true,
  "finalized": true,
  "request_commitment_b64": "<exact request value>",
  "authorization_id_b64": "<canonical Actum intent/authorization identity>",
  "token_class": "c2048"
}
```

The authorization identifier is hashed before persistence and becomes the gateway's replay key.
Any negative decision should return `401`, `403`, or `422`. Verifier faults return another non-2xx
status. The gateway treats negative decisions as invalid payment and verifier faults as unavailable;
both fail before provider execution.

## Request commitment

The gateway recursively sorts JSON object keys and serializes this ticket-free request projection:

- request ID;
- model;
- messages, including provider-compatible message extensions;
- max tokens, temperature, and stream flag;
- token class;
- provider options.

It then computes SHA-256 over:

```text
"ZEROK-ACTUM-INFERENCE-AUTHORIZATION-V1\0"
|| u64_be(json_length)
|| canonical_json
```

Client implementations should use the shared SDK helper rather than recreating this algorithm.

## Limits and failure behavior

- Evidence is capped at 2 MiB before base64 transport.
- Verifier requests default to a 10-second timeout.
- Plain HTTP requires the explicit local-development override.
- Missing, malformed, substituted, non-finalized, or token-class-mismatched responses fail closed.
- Gateway replay reservation happens before provider execution and is durably marked spent after a
  successful response.

The `actum-verifier-dev` container in ZeroK validates contract wiring only. It is not an
ActiveChain finality implementation and cannot be promoted to production.
