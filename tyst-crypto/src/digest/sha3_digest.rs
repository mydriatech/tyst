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

//! NIST FIPS 202 SHA3 message digest algorithms.
//!
//! Based on the Keccak message digest algorithm.

use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::CryptoRegistry;

use super::keccak_digest::KeccakDigest;

/// Factory for [Sha3Digest].
pub struct Sha3DigestFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Sha3DigestFactory {
    // https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
    /// `2.16.840.1.101.3.4.2.7`
    ///
    // joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-224(7)
    const OID_SHA3_224: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 7];
    /// `2.16.840.1.101.3.4.2.8`
    ///
    // joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-256(8)
    const OID_SHA3_256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 8];
    /// `2.16.840.1.101.3.4.2.9`
    ///
    // joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-384(9)
    const OID_SHA3_384: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 9];
    /// `2.16.840.1.101.3.4.2.10`
    ///
    // joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-512(10)
    const OID_SHA3_512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 10];
}

impl Default for Sha3DigestFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("SHA3-224", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_SHA3_224)),
                AlgorithmMetaData::new("SHA3-256", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_SHA3_256)),
                AlgorithmMetaData::new("SHA3-384", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_SHA3_384)),
                AlgorithmMetaData::new("SHA3-512", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_SHA3_512)),
            ],
        }
    }
}

impl Factory for Sha3DigestFactory {
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
        match algorithm_name {
            // TODO: Drop SHA3-224
            "SHA3-224" => Box::new(Sha3Digest::new(224)),
            "SHA3-256" => Box::new(Sha3Digest::new(256)),
            "SHA3-384" => Box::new(Sha3Digest::new(384)),
            "SHA3-512" => Box::new(Sha3Digest::new(512)),
            _ => panic!("not implemented"),
        }
    }
}

/// SHA-3 message digest implementation based on [KeccakDigest].
pub struct Sha3Digest {
    keccek_digest: KeccakDigest,
}

impl Digest for Sha3Digest {
    fn update(&mut self, data: &[u8]) {
        self.keccek_digest.update(data)
    }

    fn output(&mut self, out: &mut [u8]) {
        // This padding is required for SHA3
        if !self.keccek_digest.get_squeezing() {
            self.keccek_digest.absorb_bits(0x02, 2);
        }
        self.keccek_digest
            .output(&mut out[0..self.get_digest_size_bits() / 8]);
    }

    fn get_digest_size_bits(&self) -> usize {
        self.keccek_digest.get_digest_size_bits()
    }

    fn get_algorithm_name(&self) -> String {
        Self::ALGORITHM_NAME_PREFIX.to_string() + &self.get_digest_size_bits().to_string()
    }

    fn get_algorithm_oid(&self) -> Option<Vec<u32>> {
        Some(match self.get_digest_size_bits() {
            224 => Sha3DigestFactory::OID_SHA3_224.to_vec(),
            256 => Sha3DigestFactory::OID_SHA3_256.to_vec(),
            384 => Sha3DigestFactory::OID_SHA3_384.to_vec(),
            512 => Sha3DigestFactory::OID_SHA3_512.to_vec(),
            _ => panic!("not implemented"),
        })
    }

    fn reset(&mut self) {
        self.keccek_digest.reset()
    }
}

#[allow(dead_code)]
impl Sha3Digest {
    #[doc(hidden)]
    pub const ALGORITHM_NAME_PREFIX: &str = "SHA3-";

    #[doc(hidden)]
    const ALLOWED_BIT_LENGTHS: [usize; 4] = [224, 256, 384, 512];

    #[doc(hidden)]
    /// Return a new instance
    pub fn new(bit_length: usize) -> Self {
        if !Self::ALLOWED_BIT_LENGTHS.contains(&bit_length) {
            panic!("Bit length must be one of {:?}.", Self::ALLOWED_BIT_LENGTHS);
        }
        Self {
            keccek_digest: KeccakDigest::new(bit_length),
        }
    }
}

// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VECTOR: &[(usize, &'static str, &'static str)] = &[
        (
            224,
            "",
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        ),
        (
            224,
            // Len 680
            "8b5d77a906c7ec7563af7551a796e5d5dcf02c42121d7b13a49aa9d4bc79d637190e4e6510ecaf92d1104fd4ec5bd8351446350722d1b2775dbc5e65f8fab473dc637b5ca8a9eb88f68d11dde15275d7c472f9db43",
            "9337537de482f0cf88cad6b86e195a1e422e59cc60d41d0eca8b0091",
        ),
        (
            256,
            "",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            256,
            // Len 680
            "939c61e68af5e2fdb75a2eebb159a85b0c87a126ce22701622f5c5ef517c3ab0ed492b1650a6c862457c685c04732198645b95f84ccb0e726a07ce132827a044dc76b34d3f19a81721f1ea365bc23e2604949bd5e8",
            "121057b0b9a627be07dc54e7d1b719f0a3df9d20d29a03a38b5df0a51503df93",
        ),
        (
            384,
            "",
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        ),
        (
            384,
            // Len 680
            "009dd821cbed1235880fe647e191fe6f6555fdc98b8aad0ff3da5a6df0e5799044ef8e012ad54cb19a46fdd5c82f24f3ee77613d4bed961f6b7f4814aaac48bdf43c9234ce2e759e9af2f4ff16d86d5327c978dad5",
            "02a09d37d31e4365c26bec0eaacecf29eea4e8d21ab915dd605248764d964f10ebb8fafdb591982d33869a1d08a7e313",
        ),
        (
            512,
            "",
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        ),
        (
            512,
            // Len 576
            "0ce9f8c3a990c268f34efd9befdb0f7c4ef8466cfdb01171f8de70dc5fefa92acbe93d29e2ac1a5c2979129f1ab08c0e77de7924ddf68a209cdfa0adc62f85c18637d9c6b33f4ff8",
            "b018a20fcf831dde290e4fb18c56342efe138472cbe142da6b77eea4fce52588c04c808eb32912faa345245a850346faec46c3a16d39bd2e1ddb1816bc57d2da",
        ),
    ];

    #[test]
    fn test_vectors() {
        crate::test::common::init_logger();
        for (bit_length, msg, expected_digest_as_hex) in TEST_VECTOR.iter().cloned() {
            let hash_as_hex = &tyst_encdec::hex::encode(
                &Sha3Digest::new(bit_length).hash(&tyst_encdec::hex::decode(msg).unwrap()),
            );
            assert_eq!(
                hash_as_hex.len()*4, bit_length,
                "Failed to generate the correct hash size for bit_length '{bit_length}' and messages '{msg}'."
            );
            assert_eq!(
                hash_as_hex, expected_digest_as_hex,
                "Failed to generate the correct hash for bit_length '{bit_length}' and messages '{msg}'."
            );
        }
    }
}
