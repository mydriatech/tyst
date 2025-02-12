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

//! External implementation of Secure Hash Algorithm 2 (SHA-2) from
//! [RustCrypto: Hashes](https://github.com/RustCrypto/hashes/).

extern crate sha2;

use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::CryptoRegistry;

/// Factory for [Sha2Digest].
pub struct Sha2DigestFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Default for Sha2DigestFactory {
    fn default() -> Self {
        Self {
            // nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) }
            // hashAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 2 }
            // id-sha256 OBJECT IDENTIFIER ::= { hashAlgs 1 }
            // 2.16.840.1.101.3.4.2.1
            provided: vec![
                AlgorithmMetaData::new("SHA-224", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.4"),
                AlgorithmMetaData::new("SHA-256", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.1"),
                AlgorithmMetaData::new("SHA-384", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.2"),
                AlgorithmMetaData::new("SHA-512", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.3"),
                AlgorithmMetaData::new("SHA-512-224", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.5"),
                AlgorithmMetaData::new("SHA-512-256", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.6"),
            ],
        }
    }
}

impl Factory for Sha2DigestFactory {
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
        //let output_bits = params.get_output_bits();
        Box::new(Sha2Digest::new(algorithm_name))
    }
}

/// Wrapper of external SHA-2 implementation.
enum Sha2Digest {
    #[doc(hidden)]
    Sha224 { hasher: sha2::Sha224 },
    #[doc(hidden)]
    Sha256 { hasher: sha2::Sha256 },
    #[doc(hidden)]
    Sha384 { hasher: sha2::Sha384 },
    #[doc(hidden)]
    Sha512 { hasher: sha2::Sha512 },
    #[doc(hidden)]
    Sha512_224 { hasher: sha2::Sha512_224 },
    #[doc(hidden)]
    Sha512_256 { hasher: sha2::Sha512_256 },
}

impl Sha2Digest {
    #[doc(hidden)]
    /// Create a new instance
    fn new(algorithm_name: &str) -> Self {
        match algorithm_name {
            "SHA-224" => Sha2Digest::Sha224 {
                hasher: self::sha2::Digest::new(),
            },
            "SHA-256" => Sha2Digest::Sha256 {
                hasher: self::sha2::Digest::new(),
            },
            "SHA-384" => Sha2Digest::Sha384 {
                hasher: self::sha2::Digest::new(),
            },
            "SHA-512" => Sha2Digest::Sha512 {
                hasher: self::sha2::Digest::new(),
            },
            "SHA-512-224" => Sha2Digest::Sha512_224 {
                hasher: self::sha2::Digest::new(),
            },
            "SHA-512-256" => Sha2Digest::Sha512_256 {
                hasher: self::sha2::Digest::new(),
            },
            _ => panic!("not implemented"),
        }
    }
}
impl Digest for Sha2Digest {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha224 { ref mut hasher } => self::sha2::Digest::update(hasher, data),
            Self::Sha256 { ref mut hasher } => self::sha2::Digest::update(hasher, data),
            Self::Sha384 { ref mut hasher } => self::sha2::Digest::update(hasher, data),
            Self::Sha512 { ref mut hasher } => self::sha2::Digest::update(hasher, data),
            Self::Sha512_224 { ref mut hasher } => self::sha2::Digest::update(hasher, data),
            Self::Sha512_256 { ref mut hasher } => self::sha2::Digest::update(hasher, data),
        }
    }

    fn output(&mut self, out: &mut [u8]) {
        match self {
            Self::Sha224 { ref mut hasher } => {
                out.copy_from_slice(&self::sha2::Digest::finalize_reset(hasher))
            }
            Self::Sha256 { ref mut hasher } => {
                out.copy_from_slice(&self::sha2::Digest::finalize_reset(hasher))
            }
            Self::Sha384 { ref mut hasher } => {
                out.copy_from_slice(&self::sha2::Digest::finalize_reset(hasher))
            }
            Self::Sha512 { ref mut hasher } => {
                out.copy_from_slice(&self::sha2::Digest::finalize_reset(hasher))
            }
            Self::Sha512_224 { ref mut hasher } => {
                out.copy_from_slice(&self::sha2::Digest::finalize_reset(hasher))
            }
            Self::Sha512_256 { ref mut hasher } => {
                out.copy_from_slice(&self::sha2::Digest::finalize_reset(hasher))
            }
        };
    }

    fn get_digest_size_bits(&self) -> usize {
        match self {
            Self::Sha224 { hasher: _ } => 224,
            Self::Sha256 { hasher: _ } => 256,
            Self::Sha384 { hasher: _ } => 384,
            Self::Sha512 { hasher: _ } => 512,
            Self::Sha512_224 { hasher: _ } => 224,
            Self::Sha512_256 { hasher: _ } => 256,
        }
    }

    fn get_algorithm_name(&self) -> String {
        match self {
            Self::Sha224 { hasher: _ } => "SHA-224".to_string(),
            Self::Sha256 { hasher: _ } => "SHA-256".to_string(),
            Self::Sha384 { hasher: _ } => "SHA-384".to_string(),
            Self::Sha512 { hasher: _ } => "SHA-512".to_string(),
            Self::Sha512_224 { hasher: _ } => "SHA-512-224".to_string(),
            Self::Sha512_256 { hasher: _ } => "SHA-512-256".to_string(),
        }
    }

    fn reset(&mut self) {
        match self {
            Self::Sha224 { ref mut hasher } => self::sha2::Digest::reset(hasher),
            Self::Sha256 { ref mut hasher } => self::sha2::Digest::reset(hasher),
            Self::Sha384 { ref mut hasher } => self::sha2::Digest::reset(hasher),
            Self::Sha512 { ref mut hasher } => self::sha2::Digest::reset(hasher),
            Self::Sha512_224 { ref mut hasher } => self::sha2::Digest::reset(hasher),
            Self::Sha512_256 { ref mut hasher } => self::sha2::Digest::reset(hasher),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VECTOR: &[(&'static str, &'static str, &'static str)] = &[
        (
            "SHA-224",
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        ),
        (
            "SHA-256",
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "SHA-384",
            "",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        (
            "SHA-512",
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            "SHA-512-224",
            "",
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        ),
        (
            "SHA-512-256",
            "",
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        ),
    ];

    #[test]
    fn test_vectors() {
        crate::test::common::init_logger();
        for (algorithm_name, msg, expected_digest_as_hex) in TEST_VECTOR.iter().cloned() {
            let hash_as_hex = &tyst_encdec::hex::encode(
                &Sha2Digest::new(algorithm_name).hash(&tyst_encdec::hex::decode(msg).unwrap()),
            );
            assert_eq!(
                hash_as_hex, expected_digest_as_hex,
                "Failed to generate the correct hash for '{algorithm_name}' and messages '{msg}'."
            );
        }
    }
}
