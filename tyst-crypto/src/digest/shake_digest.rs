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

//! NIST FIPS 202 SHAKE extendable-output functions (XOFs) message digest
//! algorithms.
//!
//! Based on the Keccak message digest algorithm.
use super::keccak_digest::KeccakDigest;
use tyst_oids as oids;
use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::CryptoRegistry;

/// Factory for [ShakeDigest].
pub struct ShakeDigestFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Default for ShakeDigestFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("SHAKE128", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(oids::digest::SHAKE128)),
                AlgorithmMetaData::new("SHAKE256", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(oids::digest::SHAKE256)),
            ],
        }
    }
}

impl Factory for ShakeDigestFactory {
    type Type = dyn Digest;
    type Parameters = DigestParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        _registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        params: Self::Parameters,
    ) -> Box<Self::Type> {
        let output_bits = params.output_bits();
        match algorithm_name {
            "SHAKE128" => Box::new(ShakeDigest::new(128, output_bits)),
            "SHAKE256" => Box::new(ShakeDigest::new(256, output_bits)),
            _ => panic!("not implemented"),
        }
    }
}

/// SHAKE message digest implementation based on [KeccakDigest].
pub struct ShakeDigest {
    keccek_digest: KeccakDigest,
    digest_size_bits: usize,
}

impl ShakeDigest {
    #[doc(hidden)]
    pub const ALGORITHM_NAME_PREFIX: &str = "SHAKE";

    #[doc(hidden)]
    const ALLOWED_BIT_LENGTHS: [usize; 2] = [128, 256];

    #[doc(hidden)]
    /// Return a new instance
    pub fn new(bit_length: usize, output_bits: Option<usize>) -> Self {
        if !Self::ALLOWED_BIT_LENGTHS.contains(&bit_length) {
            panic!("Bit length must be one of {:?}.", Self::ALLOWED_BIT_LENGTHS);
        }
        let digest_size_bits = output_bits.unwrap_or(bit_length * 2);
        assert!(digest_size_bits % 8 == 0);
        Self {
            keccek_digest: KeccakDigest::new(bit_length),
            // Use sane defaults for output
            digest_size_bits,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.keccek_digest.update(data)
    }

    fn output(&mut self, out: &mut [u8]) {
        // This padding is required for SHAKE
        if !self.keccek_digest.get_squeezing() {
            self.keccek_digest.absorb_bits(0x0f, 4);
        }
        self.keccek_digest.output(out);
    }

    fn get_digest_size_bits(&self) -> usize {
        self.digest_size_bits
    }

    fn get_algorithm_name(&self) -> String {
        Self::ALGORITHM_NAME_PREFIX.to_string() + &self.get_digest_size_bits().to_string()
    }

    fn reset(&mut self) {
        self.keccek_digest.reset()
    }
}

impl Digest for ShakeDigest {
    fn update(&mut self, data: &[u8]) {
        ShakeDigest::update(self, data)
    }

    fn output(&mut self, out: &mut [u8]) {
        ShakeDigest::output(self, out)
    }

    fn get_digest_size_bits(&self) -> usize {
        ShakeDigest::get_digest_size_bits(self)
    }

    fn get_algorithm_name(&self) -> String {
        ShakeDigest::get_algorithm_name(self)
    }

    fn get_algorithm_oid(&self) -> Option<Vec<u32>> {
        Some(match self.get_digest_size_bits() {
            128 => oids::digest::SHAKE128.to_vec(),
            256 => oids::digest::SHAKE256.to_vec(),
            _ => panic!("not implemented"),
        })
    }

    fn reset(&mut self) {
        ShakeDigest::reset(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VECTOR: &[(usize, &'static str, &'static str)] = &[
        (
            128,
            "",
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        ),
        (
            256,
            "",
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        ),
    ];

    #[test]
    fn test_vectors() {
        crate::test::common::init_logger();
        for (bit_length, msg, expected_digest_as_hex) in TEST_VECTOR.iter().cloned() {
            let hash_as_hex = &tyst_encdec::hex::encode(
                &ShakeDigest::new(bit_length, Some(bit_length * 2))
                    .hash(&tyst_encdec::hex::decode(msg).unwrap()),
            );
            assert_eq!(
                hash_as_hex.len()*4, bit_length*2,
                "Failed to generate the correct hash size for bit_length '{bit_length}' and messages '{msg}'."
            );
            assert_eq!(
                hash_as_hex, expected_digest_as_hex,
                "Failed to generate the correct hash for bit_length '{bit_length}' and messages '{msg}'."
            );
        }
    }
}
