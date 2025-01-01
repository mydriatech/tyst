/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! Symmetric Cryptography using SHAKE as described in NIST FIPS 204 3.7.

use tyst_traits::digest::Digest;

use crate::digest::shake_digest::ShakeDigest;

/// Symmetric Cryptography using SHAKE as described in NIST FIPS 204 3.7.
///
/// This object holds two message digest implementations: one SHAKE128 and one
/// SHAKE256.
pub struct ShakeSymmetric {
    digest128: ShakeDigest,
    digest256: ShakeDigest,
}

impl std::fmt::Debug for ShakeSymmetric {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "**redacted**")
    }
}

impl ShakeSymmetric {
    /// SHAKE128 block size ("rate" in Keccak) in bytes
    pub const STREAM_128_BLOCK_BYTES: usize = 168;
    /// SHAKE256 block size ("rate" in Keccak) in bytes
    pub const STREAM_256_BLOCK_BYTES: usize = 136;

    /// Return a new instance.
    pub fn new() -> Self {
        Self {
            digest128: ShakeDigest::new(128, None),
            digest256: ShakeDigest::new(256, None),
        }
    }

    /// Re-initialize the `digest`.
    fn stream_init(digest: &mut ShakeDigest, seed: &[u8], nonce: i16) {
        digest.reset();
        digest.update(seed);
        digest.update(&nonce.to_le_bytes());
    }

    /// Re-initialize the SHAKE128 message digest.
    pub fn stream_128_init(&mut self, seed: &[u8], nonce: i16) {
        Self::stream_init(&mut self.digest128, seed, nonce);
    }

    /// Re-initialize the SHAKE256 message digest.
    pub fn stream_256_init(&mut self, seed: &[u8], nonce: i16) {
        Self::stream_init(&mut self.digest256, seed, nonce);
    }

    /// Write the output state (hash) of the SHAKE128 message digest to `output`.
    pub fn stream_128_squeeze_blocks(&mut self, output: &mut [u8], offset: usize, size: usize) {
        self.digest128.output(&mut output[offset..offset + size])
    }

    /// Write the output state (hash) of the SHAKE256 message digest to `output`.
    pub fn stream_256_squeeze_blocks(&mut self, output: &mut [u8], offset: usize, size: usize) {
        self.digest256.output(&mut output[offset..offset + size])
    }
}
