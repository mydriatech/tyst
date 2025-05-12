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

//! External implementation of Secure Hash Algorithm 1 (SHA-1) from
//! [RustCrypto: Hashes](https://github.com/RustCrypto/hashes/).

extern crate sha1;

use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::CryptoRegistry;

/// Factory for [Sha1Digest].
pub struct Sha1DigestFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Sha1DigestFactory {
    /// `1.3.14.3.2.26`
    ///
    // iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)
    #[allow(dead_code)]
    const OID_SHA_1: &[u32] = &[1, 3, 14, 3, 2, 26];
}

impl Default for Sha1DigestFactory {
    fn default() -> Self {
        Self {
            provided: vec![AlgorithmMetaData::new("SHA-1", env!("CARGO_PKG_NAME"))
                .set_oid(&tyst_encdec::oid::as_string(Self::OID_SHA_1))],
        }
    }
}

impl Factory for Sha1DigestFactory {
    type Type = dyn Digest;
    type Parameters = DigestParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        _registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        _params: Self::Parameters,
    ) -> Box<Self::Type> {
        Box::new(Sha1Digest::new(algorithm_name))
    }
}

/// Wrapper of external SHA-1 implementation.
struct Sha1Digest {
    hasher: sha1::Sha1,
}

impl Sha1Digest {
    #[doc(hidden)]
    /// Create a new instance
    fn new(algorithm_name: &str) -> Self {
        match algorithm_name {
            "SHA-1" => Sha1Digest {
                hasher: self::sha1::Digest::new(),
            },
            _ => panic!("not implemented"),
        }
    }
}
impl Digest for Sha1Digest {
    fn update(&mut self, data: &[u8]) {
        self::sha1::Digest::update(&mut self.hasher, data)
    }

    fn output(&mut self, out: &mut [u8]) {
        out.copy_from_slice(&self::sha1::Digest::finalize_reset(&mut self.hasher));
    }

    fn get_digest_size_bits(&self) -> usize {
        160
    }

    fn get_algorithm_name(&self) -> String {
        "SHA-1".to_string()
    }

    fn get_algorithm_oid(&self) -> Option<Vec<u32>> {
        Some(Sha1DigestFactory::OID_SHA_1.to_vec())
    }

    fn reset(&mut self) {
        self::sha1::Digest::reset(&mut self.hasher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VECTOR: &[(&'static str, &'static str, &'static str)] =
        &[("SHA-1", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709")];

    #[test]
    fn test_vectors() {
        crate::test::common::init_logger();
        for (algorithm_name, msg, expected_digest_as_hex) in TEST_VECTOR.iter().cloned() {
            let hash_as_hex = &tyst_encdec::hex::encode(
                &Sha1Digest::new(algorithm_name).hash(&tyst_encdec::hex::decode(msg).unwrap()),
            );
            assert_eq!(
                hash_as_hex, expected_digest_as_hex,
                "Failed to generate the correct hash for '{algorithm_name}' and messages '{msg}'."
            );
        }
    }
}
