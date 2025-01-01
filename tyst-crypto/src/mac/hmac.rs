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

//! SHA3 versions of Keyed-Hashing for Message Authentication (HMAC) defined in
//! [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).

use tyst_traits::digest::Digest;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::mac::Mac;
use tyst_traits::mac::MacKey;
use tyst_traits::mac::MacParams;
use tyst_traits::mac::ToMacKey;
use tyst_traits::CryptoRegistry;

/// Factory for [HmacMac].
pub struct HmacMacFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Default for HmacMacFactory {
    /*
    oint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2)
    → 2.16.840.1.101.3.4.2

    id-hmacWithSHA3-224 OBJECT IDENTIFIER ::= { hashAlgs 13 }
    id-hmacWithSHA3-256 OBJECT IDENTIFIER ::= { hashAlgs 14 }
    id-hmacWithSHA3-384 OBJECT IDENTIFIER ::= { hashAlgs 15 }
    id-hmacWithSHA3-512 OBJECT IDENTIFIER ::= { hashAlgs 16 }

    Note that SHA3-224 should not be used after 2023.
    */
    fn default() -> Self {
        Self {
            provided: vec![
                //AlgorithmMetaData::new("HMAC-SHA3-224", env!("CARGO_PKG_NAME")).set_oid("2.16.840.1.101.3.4.2.13"),
                AlgorithmMetaData::new("HMAC-SHA3-256", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.14"),
                AlgorithmMetaData::new("HMAC-SHA3-384", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.15"),
                AlgorithmMetaData::new("HMAC-SHA3-512", env!("CARGO_PKG_NAME"))
                    .set_oid("2.16.840.1.101.3.4.2.16"),
            ],
        }
    }
}

impl Factory for HmacMacFactory {
    type Type = dyn Mac;
    type Parameters = MacParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        _params: Self::Parameters,
    ) -> Box<Self::Type> {
        match algorithm_name {
            //"HMAC-SHA3-256" => Box::new(Hmac::new(Digests::default().by_name("SHA3-224", None).unwrap(), 144)),
            "HMAC-SHA3-256" => {
                let digest = registry.digests().by_name("SHA3-256").unwrap();
                Box::new(HmacMac::<136>::new(registry, digest))
            }
            "HMAC-SHA3-384" => {
                let digest = registry.digests().by_name("SHA3-384").unwrap();
                Box::new(HmacMac::<104>::new(registry, digest))
            }
            "HMAC-SHA3-512" => {
                let digest = registry.digests().by_name("SHA3-512").unwrap();
                Box::new(HmacMac::<72>::new(registry, digest))
            }
            _ => panic!("not implemented"),
        }
    }
}

/**
# HMAC: Keyed-Hashing for Message Authentication

Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).

[RFC 2104 errata eid4809](https://www.rfc-editor.org/errata/eid4809) and
NIST SP 800-224 ipd section 6.2 discourages use of a key that is longer than
B bytes to avoid key recovery in some scenarios.

Byte-length (B) is defined as:

* 136 bytes for `HMAC-SHA3-256`
* 104 bytes for `HMAC-SHA3-384`
* 72 bytes for `HMAC-SHA3-512`

 */
#[allow(dead_code)]
pub struct HmacMac<const B: usize> {
    #[allow(clippy::redundant_allocation)]
    registry: Box<&'static dyn CryptoRegistry>,
    digest: Box<dyn Digest>,
    // B long (e.g. 136 bytes long for SHA3-256)
    inner_padding: [u8; B],
    outer_padding: [u8; B],
    inner_padding_initialized: bool,
}

impl<const B: usize> HmacMac<B> {
    /// Inner pad from RFC 2104 2.
    const IPAD: u8 = 0x36;
    /// Outer pad from RFC 2104 2.
    const OPAD: u8 = 0x5c;

    #[allow(clippy::redundant_allocation)]
    pub fn new(registry: Box<&'static dyn CryptoRegistry>, digest: Box<dyn Digest>) -> Self {
        Self {
            registry,
            digest,
            inner_padding: [0u8; B],
            outer_padding: [0u8; B],
            inner_padding_initialized: false,
        }
    }
}

impl<const B: usize> Mac for HmacMac<B> {
    fn generate_key(&self) -> Box<dyn MacKey> {
        let mut target = vec![0u8; B];
        self.registry.prng_fill_with_random(None, &mut target);
        target.to_mac_key()
    }

    fn init(&mut self, key: &Box<dyn MacKey>) {
        let key = key.try_as_bytes().unwrap();
        let key = key.as_slice();
        self.digest.reset();
        let mut key_size = key.len();
        // Applications that use keys longer than B bytes will first hash the
        // key using H and then use the resultant L byte string as the actual
        // key to HMAC.
        if key.len() > self.inner_padding.len() {
            if log::log_enabled!(log::Level::Debug) {
                log::debug!(
                    "Using a key longer than B is discouraged due to errate EID 4809 of RFC 2104."
                );
            }
            self.digest.update(key);
            self.digest.finalize(&mut self.inner_padding);
            // L
            key_size = self.digest.get_digest_size_bits() >> 3;
        } else {
            self.inner_padding[0..key.len()].clone_from_slice(key);
        }
        // (1) append zeros to the end of K to create a B byte string
        for i in key_size..self.inner_padding.len() {
            self.inner_padding[i] = 0;
        }
        // B (e.g. 136 bytes long for SHA3-256)
        self.outer_padding.clone_from_slice(&self.inner_padding);
        for i in 0..self.inner_padding.len() {
            // (2) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with ipad
            self.inner_padding[i] ^= Self::IPAD;
            // (5) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
            self.outer_padding[i] ^= Self::OPAD;
        }
        self.inner_padding_initialized = true;
        // Start performing inner hash
        // (Text will be appended directly to the digest after adding "K XOR Idap")
        self.digest.update(&self.inner_padding);
    }

    fn update(&mut self, data: &[u8]) {
        if !self.inner_padding_initialized {
            panic!("MAC update invoked before init.");
        }
        self.digest.update(data);
    }

    fn finalize(&mut self, out: &mut [u8]) {
        if !self.inner_padding_initialized {
            panic!("MAC finalize invoked before init.");
        }
        // Finalize inner hash (leaving the digest reset)
        let digest_bytes = self.digest.get_digest_size_bits() / 8;
        // Potentially over-alloc on stack
        if digest_bytes > 512 / 8 {
            panic!("Unexpectedly large digest size.")
        }
        let mut inner_hash = [0u8; 512 / 8];
        //let mut inner_hash = vec![0u8; self.digest.get_digest_size_bits() / 8];
        self.digest.finalize(&mut inner_hash[0..digest_bytes]);
        // Performing outer hash (leaving the digest reset)
        self.digest.update(&self.outer_padding);
        self.digest.update(&inner_hash[0..digest_bytes]);
        self.digest.finalize(out);
        // Start performing next inner hash
        self.digest.update(&self.inner_padding);
    }

    fn reset(&mut self) {
        // Start performing next inner hash
        self.digest.reset();
        self.digest.update(&self.inner_padding);
    }

    fn get_mac_size_bits(&self) -> usize {
        self.digest.get_digest_size_bits()
    }

    fn get_algorithm_name(&self) -> String {
        "HMAC-".to_string() + &self.digest.get_algorithm_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha3_digest::Sha3Digest;
    use std::ops::Deref;
    use std::sync::LazyLock;
    use tyst_traits::mac::ToMacKey;

    const KEY: &'static str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const MESSAGE: &'static str = "4869205468657265";
    const OUTPUTS: &[(usize,usize,&str)] = &[
        (256, 136, "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"),
        (384, 104, "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd"),
        (512, 72, "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"),
    ];

    pub struct DummyCryptoRegistry {}
    impl CryptoRegistry for DummyCryptoRegistry {}
    static DUMMY_REGISTRY: LazyLock<DummyCryptoRegistry> = LazyLock::new(|| DummyCryptoRegistry {});

    #[test]
    fn test_vectors() {
        crate::test::common::init_logger();
        let key_bytes = tyst_encdec::hex::decode(KEY);
        let msg_bytes = tyst_encdec::hex::decode(MESSAGE);
        log::info!("message: {}", String::from_utf8(msg_bytes.clone()).unwrap());
        for item in OUTPUTS {
            //let mut mac = HmacMacFactory::default().new_by_name(item.0, );
            let mut mac: Box<dyn Mac> = match item.1 {
                136 => Box::new(HmacMac::<136>::new(
                    Box::new(DUMMY_REGISTRY.deref()),
                    Box::new(Sha3Digest::new(item.0)),
                )),
                104 => Box::new(HmacMac::<104>::new(
                    Box::new(DUMMY_REGISTRY.deref()),
                    Box::new(Sha3Digest::new(item.0)),
                )),
                72 => Box::new(HmacMac::<72>::new(
                    Box::new(DUMMY_REGISTRY.deref()),
                    Box::new(Sha3Digest::new(item.0)),
                )),
                _ => panic!("Unsupported!"),
            };
            mac.init(&key_bytes.clone().to_mac_key());
            //mac.reset();
            mac.update(&msg_bytes);
            let mut out = vec![0u8; mac.get_mac_size_bits() >> 3];
            mac.finalize(&mut out);
            let actual = tyst_encdec::hex::encode(&out);
            assert_eq!(
                actual, item.2,
                "Generated an incorrect output for {}.",
                item.0
            );
        }
    }
}
