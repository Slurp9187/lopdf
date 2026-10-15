//! Decrypting one stream's data a chunk at a time, for a caller that never holds the whole stream.
//!
//! A [`ChunkDecipher`] writes into a buffer its caller lends it and holds at most one AES block of
//! its own, so nothing here grows with the stream. Everything it holds that is as good as the key or
//! the plaintext is wiped on drop.

use super::DecryptionError;
use super::pkcs5::Pkcs5;
use super::rc4::Rc4Keystream;
use aes::cipher::consts::U16;
use aes::cipher::{BlockModeDecrypt, BlockSizeUser, KeyIvInit};
use zeroize::{Zeroize as _, Zeroizing};

/// How many bytes beyond its input [`ChunkDecipher::update`] may write: AES releases a block it held
/// back. It is also enough for everything [`ChunkDecipher::finish`] writes.
pub const MAX_EXPANSION: usize = 16;

/// Decrypts one stream object's data, fed a chunk at a time.
pub trait ChunkDecipher: Send {
    /// How many bytes from the end of the ciphertext [`plaintext_len`](Self::plaintext_len) needs:
    /// 0 when decryption keeps the length.
    fn tail_len(&self) -> usize;

    /// The plaintext length of a stream whose ciphertext is `ciphertext_len` bytes long and whose
    /// last [`tail_len`](Self::tail_len) bytes are `tail`, known before any of it is decrypted. A
    /// ciphertext shorter than the tail needs no tail.
    fn plaintext_len(&self, ciphertext_len: usize, tail: &[u8]) -> Result<usize, DecryptionError>;

    /// Decrypts the next `input` bytes into `output` and returns how many bytes it wrote. `output`
    /// must hold at least `input.len() + MAX_EXPANSION` bytes.
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, DecryptionError>;

    /// Ends the stream: checks it is complete, writes the plaintext still held back into `output`,
    /// which must hold at least [`MAX_EXPANSION`] bytes, and returns how many bytes it wrote.
    fn finish(&mut self, output: &mut [u8]) -> Result<usize, DecryptionError>;
}

fn check_output(input: &[u8], output: &[u8]) {
    assert!(
        output.len() >= input.len() + MAX_EXPANSION,
        "a chunk decipher's output needs room for its input and MAX_EXPANSION more bytes"
    );
}

/// The Identity crypt filter: the data is not encrypted.
pub(crate) struct IdentityDecipher;

impl ChunkDecipher for IdentityDecipher {
    fn tail_len(&self) -> usize {
        0
    }

    fn plaintext_len(&self, ciphertext_len: usize, _tail: &[u8]) -> Result<usize, DecryptionError> {
        Ok(ciphertext_len)
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, DecryptionError> {
        check_output(input, output);
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }

    fn finish(&mut self, _output: &mut [u8]) -> Result<usize, DecryptionError> {
        Ok(0)
    }
}

/// RC4, whose keystream carries on from one chunk to the next.
pub(super) struct Rc4Decipher {
    keystream: Rc4Keystream,
}

impl Rc4Decipher {
    pub(super) fn new(keystream: Rc4Keystream) -> Self {
        Self { keystream }
    }
}

impl ChunkDecipher for Rc4Decipher {
    fn tail_len(&self) -> usize {
        0
    }

    fn plaintext_len(&self, ciphertext_len: usize, _tail: &[u8]) -> Result<usize, DecryptionError> {
        Ok(ciphertext_len)
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, DecryptionError> {
        check_output(input, output);
        self.keystream.apply(input, &mut output[..input.len()]);
        Ok(input.len())
    }

    fn finish(&mut self, _output: &mut [u8]) -> Result<usize, DecryptionError> {
        Ok(0)
    }
}

/// AES-CBC with PKCS#5 padding, the IV in the first 16 bytes. Each decrypted block is held back
/// until the next one arrives, because only the last block carries the padding.
pub(super) struct AesCbcDecipher<C> {
    key: Zeroizing<Vec<u8>>,
    /// The IV, the first 16 bytes of the ciphertext, as far as it has arrived.
    iv: [u8; 16],
    iv_len: usize,
    /// Set up once the IV is complete.
    cipher: Option<C>,
    /// A ciphertext block as far as it has arrived.
    partial: [u8; 16],
    partial_len: usize,
    /// The last block decrypted, not yet written.
    held: Zeroizing<[u8; 16]>,
    has_held: bool,
}

impl<C> AesCbcDecipher<C>
where
    C: KeyIvInit + BlockModeDecrypt + BlockSizeUser<BlockSize = U16> + Send,
{
    pub(super) fn new(key: &[u8]) -> Result<Self, DecryptionError> {
        // Reject a key of the wrong length now rather than once the IV has arrived.
        C::new_from_slices(key, &[0; 16]).map_err(|_| DecryptionError::InvalidKeyLength)?;

        Ok(Self {
            key: Zeroizing::new(key.to_vec()),
            iv: [0; 16],
            iv_len: 0,
            cipher: None,
            partial: [0; 16],
            partial_len: 0,
            held: Zeroizing::new([0; 16]),
            has_held: false,
        })
    }

    fn cipher_with_iv(&self, iv: &[u8]) -> Result<C, DecryptionError> {
        C::new_from_slices(&self.key, iv).map_err(|_| DecryptionError::InvalidKeyLength)
    }
}

impl<C> ChunkDecipher for AesCbcDecipher<C>
where
    C: KeyIvInit + BlockModeDecrypt + BlockSizeUser<BlockSize = U16> + Send,
{
    fn tail_len(&self) -> usize {
        32
    }

    fn plaintext_len(&self, ciphertext_len: usize, tail: &[u8]) -> Result<usize, DecryptionError> {
        if !ciphertext_len.is_multiple_of(16) {
            return Err(DecryptionError::InvalidCipherTextLength);
        }

        // Nothing to decrypt if the ciphertext is empty or holds only the IV.
        if ciphertext_len <= 16 {
            return Ok(0);
        }

        if tail.len() != 32 {
            return Err(DecryptionError::InvalidCipherTextLength);
        }

        // The block before the last one is the last block's IV, so the last block, and with it the
        // padding, decrypts on its own.
        let mut cipher = self.cipher_with_iv(&tail[..16])?;
        let mut block = Zeroizing::new([0u8; 16]);
        block.copy_from_slice(&tail[16..]);
        cipher.decrypt_block((&mut *block).into());

        let kept = Pkcs5::unpad(&*block, true).map_err(|_| DecryptionError::Padding)?.len();

        Ok(ciphertext_len - 32 + kept)
    }

    fn update(&mut self, mut input: &[u8], output: &mut [u8]) -> Result<usize, DecryptionError> {
        check_output(input, output);

        if self.iv_len < 16 {
            let n = (16 - self.iv_len).min(input.len());
            self.iv[self.iv_len..][..n].copy_from_slice(&input[..n]);
            self.iv_len += n;
            input = &input[n..];

            if self.iv_len == 16 {
                self.cipher = Some(self.cipher_with_iv(&self.iv)?);
            }
        }

        let Some(cipher) = self.cipher.as_mut() else {
            return Ok(0);
        };

        let mut written = 0;
        while !input.is_empty() {
            let n = (16 - self.partial_len).min(input.len());
            self.partial[self.partial_len..][..n].copy_from_slice(&input[..n]);
            self.partial_len += n;
            input = &input[n..];

            if self.partial_len == 16 {
                let mut block = Zeroizing::new(self.partial);
                cipher.decrypt_block((&mut *block).into());

                if self.has_held {
                    output[written..][..16].copy_from_slice(&*self.held);
                    written += 16;
                }

                *self.held = *block;
                self.has_held = true;
                self.partial_len = 0;
            }
        }

        Ok(written)
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<usize, DecryptionError> {
        assert!(
            output.len() >= MAX_EXPANSION,
            "a chunk decipher's output needs MAX_EXPANSION bytes to finish"
        );

        // An empty stream decrypts to nothing, as does one that holds only the IV.
        if self.iv_len == 0 {
            return Ok(0);
        }

        if self.iv_len < 16 || self.partial_len != 0 {
            return Err(DecryptionError::InvalidCipherTextLength);
        }

        if !self.has_held {
            return Ok(0);
        }

        let plaintext = Pkcs5::unpad(&*self.held, true).map_err(|_| DecryptionError::Padding)?;
        let n = plaintext.len();
        output[..n].copy_from_slice(plaintext);
        self.held.zeroize();
        self.has_held = false;

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::MAX_EXPANSION;
    use crate::encryption::DecryptionError;
    use crate::encryption::crypt_filters::{
        Aes128CryptFilter, Aes256CryptFilter, CryptFilter, IdentityCryptFilter, Rc4CryptFilter,
    };

    /// Decrypts `ciphertext` through `filter`'s chunk decipher, `chunk` bytes at a time, and checks
    /// the length it predicted from the tail.
    fn chunked(
        filter: &dyn CryptFilter, key: &[u8], ciphertext: &[u8], chunk: usize,
    ) -> Result<Vec<u8>, DecryptionError> {
        let mut decipher = filter
            .chunked_decrypt(key)?
            .expect("every built-in filter decrypts in chunks");

        let tail = &ciphertext[ciphertext.len().saturating_sub(decipher.tail_len())..];
        let predicted = decipher.plaintext_len(ciphertext.len(), tail);

        let mut plaintext = Vec::new();
        let mut output = vec![0u8; chunk + MAX_EXPANSION];
        for piece in ciphertext.chunks(chunk) {
            let n = decipher.update(piece, &mut output)?;
            plaintext.extend_from_slice(&output[..n]);
        }
        let n = decipher.finish(&mut output)?;
        plaintext.extend_from_slice(&output[..n]);

        assert_eq!(predicted?, plaintext.len(), "the predicted length");
        Ok(plaintext)
    }

    fn filters() -> Vec<(&'static str, Box<dyn CryptFilter>, Vec<u8>)> {
        vec![
            ("Identity", Box::new(IdentityCryptFilter), vec![]),
            ("RC4", Box::new(Rc4CryptFilter), vec![0x42; 10]),
            ("AES-128", Box::new(Aes128CryptFilter), vec![0x42; 16]),
            ("AES-256", Box::new(Aes256CryptFilter), vec![0x42; 32]),
        ]
    }

    #[test]
    fn every_chunk_split_matches_whole_buffer_decryption() {
        for (name, filter, key) in filters() {
            for len in [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000] {
                let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let ciphertext = filter.encrypt(&key, &plaintext).unwrap();
                let whole = filter.decrypt(&key, &ciphertext).unwrap();
                assert_eq!(whole, plaintext);

                for chunk in [1, 3, 7, 16, 17, 64, ciphertext.len().max(1)] {
                    let decrypted = chunked(&*filter, &key, &ciphertext, chunk).unwrap();
                    assert_eq!(decrypted, plaintext, "{name}, {len} bytes in chunks of {chunk}");
                }
            }
        }
    }

    #[test]
    fn malformed_aes_ciphertext_fails_as_whole_buffer_decryption_does() {
        let key = [0x42u8; 32];
        let ciphertext = Aes256CryptFilter.encrypt(&key, b"some plaintext").unwrap();

        let truncated = &ciphertext[..ciphertext.len() - 1];
        let mut bad_padding = ciphertext.clone();
        *bad_padding.last_mut().unwrap() ^= 0xFF;

        for (what, bytes) in [
            ("a truncated ciphertext", truncated),
            ("bad padding", &bad_padding[..]),
            ("an IV cut short", &ciphertext[..5]),
        ] {
            let whole = Aes256CryptFilter.decrypt(&key, bytes).unwrap_err();
            for chunk in [1, 7, 16, 64] {
                let mut decipher = Aes256CryptFilter.chunked_decrypt(&key).unwrap().unwrap();
                let mut output = vec![0u8; chunk + MAX_EXPANSION];
                let streamed = bytes
                    .chunks(chunk)
                    .try_for_each(|piece| decipher.update(piece, &mut output).map(drop))
                    .and_then(|()| decipher.finish(&mut output).map(drop))
                    .unwrap_err();
                assert_eq!(
                    std::mem::discriminant(&streamed),
                    std::mem::discriminant(&whole),
                    "{what} in chunks of {chunk}: {streamed:?} against {whole:?}"
                );
            }
        }
    }

    #[test]
    fn the_predicted_length_rejects_bad_padding() {
        let key = [0x42u8; 16];
        let mut ciphertext = Aes128CryptFilter.encrypt(&key, b"0123456789").unwrap();
        *ciphertext.last_mut().unwrap() ^= 0xFF;
        let decipher = Aes128CryptFilter.chunked_decrypt(&key).unwrap().unwrap();
        let tail = &ciphertext[ciphertext.len() - 32..];
        assert!(matches!(
            decipher.plaintext_len(ciphertext.len(), tail),
            Err(DecryptionError::Padding)
        ));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_up_front() {
        assert!(matches!(
            Aes256CryptFilter.chunked_decrypt(&[0u8; 16]),
            Err(DecryptionError::InvalidKeyLength)
        ));
    }
}
