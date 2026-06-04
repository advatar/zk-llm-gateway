use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::token::{pad_to_len, trim_zero_padding, TokenClass};

/// Static keypair used by the gateway to decrypt envelopes.
///
/// Store the secret key securely (env var for MVP; HSM / KMS for production).
#[derive(Clone)]
pub struct GatewayKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl GatewayKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn secret_key(&self) -> &StaticSecret {
        &self.secret
    }
}

impl Drop for GatewayKeypair {
    fn drop(&mut self) {
        // best-effort wipe
        let mut b = self.secret.to_bytes();
        b.zeroize();
    }
}

/// Client-side context needed to decrypt the gateway's encrypted response.
///
/// Keep this only in memory, and drop it after the response is decrypted.
pub struct ClientCryptoContext {
    eph_secret_bytes: [u8; 32],
    eph_pub_bytes: [u8; 32],
    gateway_public_bytes: [u8; 32],
    client_nonce_bytes: [u8; 32],
    request_id: Uuid,
    token_class: TokenClass,
}

impl ClientCryptoContext {
    pub fn token_class(&self) -> TokenClass {
        self.token_class
    }

    /// Decrypt an encrypted response from the gateway.
    pub fn open_response(&self, env: &Envelope) -> Result<Vec<u8>> {
        if env.version != Envelope::VERSION {
            return Err(anyhow!("unsupported envelope version: {}", env.version));
        }
        if env.request_id != self.request_id {
            return Err(anyhow!("request_id mismatch"));
        }
        if env.token_class != self.token_class {
            return Err(anyhow!("token class mismatch"));
        }

        let eph_pub_bytes = decode_eph_pubkey(env)?;
        if eph_pub_bytes != self.eph_pub_bytes {
            return Err(anyhow!("unexpected eph_pubkey in response"));
        }

        let client_nonce_bytes = decode_client_nonce(env)?;
        if client_nonce_bytes != self.client_nonce_bytes {
            return Err(anyhow!("client nonce mismatch"));
        }

        let nonce_bytes: [u8; 12] = B64
            .decode(&env.nonce_b64)
            .context("invalid nonce_b64")?
            .try_into()
            .map_err(|_| anyhow!("nonce wrong length"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = B64
            .decode(&env.ciphertext_b64)
            .context("invalid ciphertext_b64")?;

        let eph_secret = StaticSecret::from(self.eph_secret_bytes);
        let gateway_public = PublicKey::from(self.gateway_public_bytes);
        let shared = eph_secret.diffie_hellman(&gateway_public);
        ensure_contributory(shared.as_bytes())?;

        let key = derive_key(
            shared.as_bytes(),
            KeyDirection::Response,
            self.token_class,
            self.request_id,
            &self.client_nonce_bytes,
            &self.eph_pub_bytes,
            &self.gateway_public_bytes,
        )?;
        let aead = ChaCha20Poly1305::new(Key::from_slice(&key));

        let aad = aad_bytes(
            env.version,
            self.token_class,
            KeyDirection::Response,
            self.request_id,
            &self.client_nonce_bytes,
            &self.eph_pub_bytes,
            &self.gateway_public_bytes,
        );

        let plaintext_padded = aead
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .context("AEAD decrypt failed")?;

        Ok(trim_zero_padding(&plaintext_padded).to_vec())
    }
}

/// A relay-friendly encrypted envelope.
///
/// This is "OHTTP-inspired" but intentionally minimal:
/// - X25519 DH (ephemeral -> static)
/// - HKDF-SHA256
/// - ChaCha20-Poly1305 AEAD
///
/// The relay sees only ciphertext and cannot read prompts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version.
    ///
    /// Serialized as `v` for SDK compatibility.
    /// Legacy input alias: `version`.
    #[serde(rename = "v", alias = "version")]
    pub version: u8,
    pub token_class: TokenClass,
    /// Client-generated request id, mirrored from the encrypted request payload.
    ///
    /// The gateway authenticates this field and echoes it in the response envelope
    /// so relays cannot replay a valid response across requests in the same token class.
    pub request_id: Uuid,
    /// Base64-encoded 32-byte client nonce used to bind this request transcript.
    pub client_nonce_b64: String,
    /// Base64-encoded client ephemeral public key.
    ///
    /// Serialized as `eph_pubkey_b64` for SDK compatibility.
    /// Legacy input alias: `kem_pub_b64`.
    #[serde(rename = "eph_pubkey_b64", alias = "kem_pub_b64")]
    pub kem_pub_b64: String,
    /// Base64-encoded AEAD nonce.
    pub nonce_b64: String,
    /// Base64-encoded ciphertext.
    pub ciphertext_b64: String,
}

impl Envelope {
    pub const VERSION: u8 = 2;
}

#[derive(Debug, Copy, Clone)]
enum KeyDirection {
    Request,
    Response,
}

/// Encrypt a request for the gateway.
///
/// Returns:
/// - `Envelope` to send (possibly via relay)
/// - `ClientCryptoContext` required to decrypt the encrypted response
pub fn seal_request_for_gateway(
    gateway_public_bytes: [u8; 32],
    token_class: TokenClass,
    request_id: Uuid,
    plaintext_json: &[u8],
) -> Result<(Envelope, ClientCryptoContext)> {
    let gateway_public = PublicKey::from(gateway_public_bytes);

    // Generate an ephemeral secret (one-time per request)
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let eph_pub_bytes = eph_pub.to_bytes();

    let mut client_nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut client_nonce_bytes);

    // Pad plaintext to fixed size per token class
    let mut padded = pad_to_len(
        plaintext_json.to_vec(),
        token_class.envelope_request_plaintext_bytes(),
    )?;

    // Shared secret and request key
    let shared = eph_secret.diffie_hellman(&gateway_public);
    ensure_contributory(shared.as_bytes())?;
    let req_key = derive_key(
        shared.as_bytes(),
        KeyDirection::Request,
        token_class,
        request_id,
        &client_nonce_bytes,
        &eph_pub_bytes,
        &gateway_public_bytes,
    )?;

    let aead = ChaCha20Poly1305::new(Key::from_slice(&req_key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = aad_bytes(
        Envelope::VERSION,
        token_class,
        KeyDirection::Request,
        request_id,
        &client_nonce_bytes,
        &eph_pub_bytes,
        &gateway_public_bytes,
    );

    let ciphertext = aead
        .encrypt(
            nonce,
            Payload {
                msg: &padded,
                aad: &aad,
            },
        )
        .context("AEAD encrypt failed")?;

    // Best-effort wipe
    padded.zeroize();

    let ctx = ClientCryptoContext {
        eph_secret_bytes: eph_secret.to_bytes(),
        eph_pub_bytes,
        gateway_public_bytes,
        client_nonce_bytes,
        request_id,
        token_class,
    };

    Ok((
        Envelope {
            version: Envelope::VERSION,
            token_class,
            request_id,
            client_nonce_b64: B64.encode(client_nonce_bytes),
            kem_pub_b64: B64.encode(eph_pub_bytes),
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
        },
        ctx,
    ))
}

/// Decrypt a request envelope at the gateway.
///
/// Returns the *trimmed* JSON bytes (padding removed).
pub fn open_request_at_gateway(keypair: &GatewayKeypair, env: &Envelope) -> Result<Vec<u8>> {
    if env.version != Envelope::VERSION {
        return Err(anyhow!("unsupported envelope version: {}", env.version));
    }

    let eph_pub_bytes = decode_eph_pubkey(env)?;
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let client_nonce_bytes = decode_client_nonce(env)?;

    let nonce_bytes: [u8; 12] = B64
        .decode(&env.nonce_b64)
        .context("invalid nonce_b64")?
        .try_into()
        .map_err(|_| anyhow!("nonce wrong length"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = B64
        .decode(&env.ciphertext_b64)
        .context("invalid ciphertext_b64")?;

    let shared = keypair.secret_key().diffie_hellman(&eph_pub);
    ensure_contributory(shared.as_bytes())?;
    let gateway_public_bytes = keypair.public_bytes();
    let req_key = derive_key(
        shared.as_bytes(),
        KeyDirection::Request,
        env.token_class,
        env.request_id,
        &client_nonce_bytes,
        &eph_pub_bytes,
        &gateway_public_bytes,
    )?;

    let aead = ChaCha20Poly1305::new(Key::from_slice(&req_key));
    let aad = aad_bytes(
        env.version,
        env.token_class,
        KeyDirection::Request,
        env.request_id,
        &client_nonce_bytes,
        &eph_pub_bytes,
        &gateway_public_bytes,
    );

    let plaintext_padded = aead
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .context("AEAD decrypt failed")?;

    Ok(trim_zero_padding(&plaintext_padded).to_vec())
}

/// Encrypt a response at the gateway using the same DH context as the request.
///
/// The response is padded to a fixed size per token class.
pub fn seal_response_at_gateway(
    keypair: &GatewayKeypair,
    request_env: &Envelope,
    plaintext_json: &[u8],
) -> Result<Envelope> {
    if request_env.version != Envelope::VERSION {
        return Err(anyhow!(
            "unsupported envelope version: {}",
            request_env.version
        ));
    }

    let eph_pub_bytes = decode_eph_pubkey(request_env)?;
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let client_nonce_bytes = decode_client_nonce(request_env)?;

    let mut padded = pad_to_len(
        plaintext_json.to_vec(),
        request_env.token_class.envelope_response_plaintext_bytes(),
    )?;

    let shared = keypair.secret_key().diffie_hellman(&eph_pub);
    ensure_contributory(shared.as_bytes())?;
    let gateway_public_bytes = keypair.public_bytes();
    let resp_key = derive_key(
        shared.as_bytes(),
        KeyDirection::Response,
        request_env.token_class,
        request_env.request_id,
        &client_nonce_bytes,
        &eph_pub_bytes,
        &gateway_public_bytes,
    )?;

    let aead = ChaCha20Poly1305::new(Key::from_slice(&resp_key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = aad_bytes(
        request_env.version,
        request_env.token_class,
        KeyDirection::Response,
        request_env.request_id,
        &client_nonce_bytes,
        &eph_pub_bytes,
        &gateway_public_bytes,
    );

    let ciphertext = aead
        .encrypt(
            nonce,
            Payload {
                msg: &padded,
                aad: &aad,
            },
        )
        .context("AEAD encrypt failed")?;

    padded.zeroize();

    Ok(Envelope {
        version: Envelope::VERSION,
        token_class: request_env.token_class,
        request_id: request_env.request_id,
        client_nonce_b64: request_env.client_nonce_b64.clone(),
        kem_pub_b64: request_env.kem_pub_b64.clone(),
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn derive_key(
    shared_secret: &[u8; 32],
    dir: KeyDirection,
    token_class: TokenClass,
    request_id: Uuid,
    client_nonce: &[u8; 32],
    eph_pub: &[u8; 32],
    gateway_pub: &[u8; 32],
) -> Result<[u8; 32]> {
    let salt = binding_salt(
        Envelope::VERSION,
        token_class,
        request_id,
        client_nonce,
        eph_pub,
        gateway_pub,
    );
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = [0u8; 32];
    let info = hkdf_info(token_class, dir);
    hk.expand(&info, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

fn hkdf_info(token_class: TokenClass, dir: KeyDirection) -> Vec<u8> {
    // Binding the derived key to the direction + token class makes cross-protocol
    // confusion harder.
    let mut v = b"zk-llm-gateway-envelope-v2".to_vec();
    match dir {
        KeyDirection::Request => v.extend_from_slice(b"/req"),
        KeyDirection::Response => v.extend_from_slice(b"/resp"),
    }
    v.push(token_class.id_u8());
    v
}

fn aad_bytes(
    version: u8,
    token_class: TokenClass,
    dir: KeyDirection,
    request_id: Uuid,
    client_nonce: &[u8; 32],
    eph_pub: &[u8; 32],
    gateway_pub: &[u8; 32],
) -> Vec<u8> {
    // Additional associated data binds the ciphertext to this request transcript.
    let d = match dir {
        KeyDirection::Request => 1u8,
        KeyDirection::Response => 2u8,
    };
    let mut v = binding_material(
        b"zk-llm-gateway-envelope-aad-v2",
        version,
        token_class,
        request_id,
        client_nonce,
        eph_pub,
        gateway_pub,
    );
    v.push(d);
    v
}

fn binding_salt(
    version: u8,
    token_class: TokenClass,
    request_id: Uuid,
    client_nonce: &[u8; 32],
    eph_pub: &[u8; 32],
    gateway_pub: &[u8; 32],
) -> [u8; 32] {
    let material = binding_material(
        b"zk-llm-gateway-envelope-kdf-v2",
        version,
        token_class,
        request_id,
        client_nonce,
        eph_pub,
        gateway_pub,
    );
    Sha256::digest(material).into()
}

fn binding_material(
    label: &[u8],
    version: u8,
    token_class: TokenClass,
    request_id: Uuid,
    client_nonce: &[u8; 32],
    eph_pub: &[u8; 32],
    gateway_pub: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(label.len() + 1 + 1 + 36 + 32 + 32 + 32 + 8);
    v.extend_from_slice(label);
    v.push(version);
    v.push(token_class.id_u8());
    v.extend_from_slice(request_id.to_string().as_bytes());
    v.extend_from_slice(client_nonce);
    v.extend_from_slice(eph_pub);
    v.extend_from_slice(gateway_pub);
    v
}

fn decode_eph_pubkey(env: &Envelope) -> Result<[u8; 32]> {
    B64.decode(&env.kem_pub_b64)
        .context("invalid kem_pub_b64")?
        .try_into()
        .map_err(|_| anyhow!("kem_pub wrong length"))
}

fn decode_client_nonce(env: &Envelope) -> Result<[u8; 32]> {
    B64.decode(&env.client_nonce_b64)
        .context("invalid client_nonce_b64")?
        .try_into()
        .map_err(|_| anyhow!("client_nonce wrong length"))
}

fn ensure_contributory(shared_secret: &[u8; 32]) -> Result<()> {
    if shared_secret.iter().all(|b| *b == 0) {
        return Err(anyhow!("invalid x25519 shared secret"));
    }
    Ok(())
}
