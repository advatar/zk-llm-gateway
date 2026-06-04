use serde::{Deserialize, Serialize};

/// A coarse-grained token budget class.
///
/// The goal is to reduce linkability (and billing metadata leakage) by
/// forcing all requests into a small number of discrete buckets.
///
/// For an MVP, we treat these as *bundles* of:
/// - max prompt bytes (after JSON serialization)
/// - max completion tokens
/// - max encrypted envelope size (so the relay sees nearly-uniform ciphertext sizes)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    /// Small quick requests.
    C256,
    /// Medium requests.
    C512,
    C1024,
    C2048,
    C4096,
}

impl TokenClass {
    pub fn max_prompt_bytes(self) -> usize {
        match self {
            TokenClass::C256 => 2 * 1024,
            TokenClass::C512 => 4 * 1024,
            TokenClass::C1024 => 8 * 1024,
            TokenClass::C2048 => 16 * 1024,
            TokenClass::C4096 => 32 * 1024,
        }
    }

    /// Upper bound on completion tokens that the gateway will allow.
    pub fn max_completion_tokens(self) -> u32 {
        match self {
            TokenClass::C256 => 256,
            TokenClass::C512 => 512,
            TokenClass::C1024 => 1024,
            TokenClass::C2048 => 2048,
            TokenClass::C4096 => 4096,
        }
    }

    /// Target plaintext size before encryption (request-side).
    ///
    /// This is intentionally *larger* than `max_prompt_bytes()` to leave room for
    /// headers, ticket, and structured fields.
    pub fn envelope_request_plaintext_bytes(self) -> usize {
        match self {
            TokenClass::C256 => 8 * 1024,
            TokenClass::C512 => 12 * 1024,
            TokenClass::C1024 => 20 * 1024,
            TokenClass::C2048 => 36 * 1024,
            TokenClass::C4096 => 68 * 1024,
        }
    }

    /// Target plaintext size before encryption (response-side).
    pub fn envelope_response_plaintext_bytes(self) -> usize {
        match self {
            TokenClass::C256 => 8 * 1024,
            TokenClass::C512 => 16 * 1024,
            TokenClass::C1024 => 32 * 1024,
            TokenClass::C2048 => 64 * 1024,
            TokenClass::C4096 => 128 * 1024,
        }
    }

    pub fn id_u8(self) -> u8 {
        match self {
            TokenClass::C256 => 1,
            TokenClass::C512 => 2,
            TokenClass::C1024 => 3,
            TokenClass::C2048 => 4,
            TokenClass::C4096 => 5,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PaddingError {
    #[error("payload too large for token class (len={len}, max={max})")]
    TooLarge { len: usize, max: usize },
}

/// Pads a byte vector to `target_len` using zero bytes.
///
/// This is safe because:
/// - The padded bytes are *inside* an authenticated encryption envelope.
/// - The gateway trims the decrypted plaintext back to the JSON boundary.
pub fn pad_to_len(mut data: Vec<u8>, target_len: usize) -> Result<Vec<u8>, PaddingError> {
    if data.len() > target_len {
        return Err(PaddingError::TooLarge {
            len: data.len(),
            max: target_len,
        });
    }
    data.resize(target_len, 0u8);
    Ok(data)
}

/// Removes trailing zero padding.
pub fn trim_zero_padding(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0u8 {
        end -= 1;
    }
    &data[..end]
}

#[cfg(test)]
mod tests {
    use super::{pad_to_len, trim_zero_padding, PaddingError, TokenClass};

    #[test]
    fn token_class_limits_are_monotonic() {
        let classes = [
            TokenClass::C256,
            TokenClass::C512,
            TokenClass::C1024,
            TokenClass::C2048,
            TokenClass::C4096,
        ];

        for window in classes.windows(2) {
            let left = window[0];
            let right = window[1];

            assert!(left.max_prompt_bytes() < right.max_prompt_bytes());
            assert!(left.max_completion_tokens() < right.max_completion_tokens());
            assert!(
                left.envelope_request_plaintext_bytes() < right.envelope_request_plaintext_bytes()
            );
            assert!(
                left.envelope_response_plaintext_bytes()
                    < right.envelope_response_plaintext_bytes()
            );
            assert!(left.id_u8() < right.id_u8());
        }
    }

    #[test]
    fn pad_to_len_adds_zero_bytes() {
        let data = vec![1u8, 2, 3];
        let padded = pad_to_len(data.clone(), 8).expect("padding should succeed");
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[..3], data.as_slice());
        assert_eq!(&padded[3..], &[0u8; 5]);
    }

    #[test]
    fn padding_shared_test_vector() {
        let data = b"{\"x\":1}".to_vec();
        let padded = pad_to_len(data.clone(), 16).expect("padding should succeed");
        assert_eq!(
            padded,
            vec![0x7b, 0x22, 0x78, 0x22, 0x3a, 0x31, 0x7d, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(trim_zero_padding(&padded), data.as_slice());
    }

    #[test]
    fn pad_to_len_rejects_large_payloads() {
        let err = pad_to_len(vec![1u8, 2, 3, 4], 3).expect_err("payload should be rejected");
        match err {
            PaddingError::TooLarge { len, max } => {
                assert_eq!(len, 4);
                assert_eq!(max, 3);
            }
        }
    }

    #[test]
    fn trim_zero_padding_keeps_non_zero_suffix() {
        let data = [1u8, 2, 0, 3, 0, 0];
        let trimmed = trim_zero_padding(&data);
        assert_eq!(trimmed, &[1u8, 2, 0, 3]);
    }
}
