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

//! Password-Based Message Authentication Code 1 (PBMAC1).

use tyst_traits::mac::Mac;
use tyst_traits::mac::ToMacKey;

use super::Pbkdf2;

/// Password-Based Message Authentication Code 1 (PBMAC1) defined in
/// [RFC 8018 7.1](https://www.rfc-editor.org/rfc/rfc8018#section-7.1).
#[allow(dead_code)]
pub struct Pbmac1 {
    mac: Box<dyn Mac>,
    pbkdf2: Pbkdf2,
}

impl Pbmac1 {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-5(5) PBMAC1(14)
    pub const OID: &[u32] = &[2, 16, 840, 113549, 1, 5, 14];

    /// Return a new instance using the provided [Mac].
    pub fn new(mac: Box<dyn Mac>, pbkdf2: Pbkdf2) -> Self {
        Self { mac, pbkdf2 }
    }

    /// Get human readable implementation identifier.
    pub fn get_algorithm_name(&self) -> String {
        "PBMAC1".to_string()
    }

    /// Create password based MAC.
    pub fn pbmac(
        &mut self,
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        message: &[u8],
    ) -> Vec<u8> {
        let dk_len = self.mac.get_mac_size_bits() >> 3;
        let dk = self
            .pbkdf2
            .derive_key_with_len(password, salt, iterations, dk_len);
        self.mac.mac(dk.to_mac_key().as_ref(), message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha3_digest::Sha3Digest;
    use crate::mac::hmac::HmacMac;
    use std::ops::Deref;
    use std::sync::LazyLock;
    use tyst_encdec::hex::ToHex;
    use tyst_traits::CryptoRegistry;

    pub struct DummyCryptoRegistry {}
    impl CryptoRegistry for DummyCryptoRegistry {}
    static DUMMY_REGISTRY: LazyLock<DummyCryptoRegistry> = LazyLock::new(|| DummyCryptoRegistry {});

    // Generated test vectors
    const TEST_VECTORS: &[(&str, &str, &str, &str, usize, &str)] = &[
        // PRF: HMAC-SHA3-256
        (
            "2.16.840.1.101.3.4.2.14",
            "This message will be PBMAC1 protected.",
            "70617373776f7264",
            "73616c74",
            1,
            "1ee76da47988a6d8bd392ab267f1131d12d25bd4385ede185d7f0a0f4a9bc50b",
        ),
        (
            "2.16.840.1.101.3.4.2.14",
            "This message will be PBMAC1 protected.",
            "70617373776f7264",
            "73616c74",
            4096,
            "619046309bab7329db469e1e15caf9fda1de46e2d19ecacc73077016599bbb60",
        ),
        (
            "2.16.840.1.101.3.4.2.14",
            "This message will be PBMAC1 protected.",
            "70617373776f726450415353574f524470617373776f7264",
            "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
            4096,
            "349d8c86fe82a7c763ba03d5c2d1ae9c19ddbb64d294c2660f0f9d542f9fbbb0",
        ),
        // PRF: HMAC-SHA3-512
        (
            "2.16.840.1.101.3.4.2.16",
            "This message will be PBMAC1 protected.",
            "70617373776f7264",
            "73616c74",
            1,
            "63c75cc9119f5674fbfc7a401511e98babad960c74955c29d27e287c8d18d1d15aa23cd4157801fc78e08f7982c667fcd048ea6e94a43a3737ecd46273541692",
        ),
        (
            "2.16.840.1.101.3.4.2.16",
            "This message will be PBMAC1 protected.",
            "70617373776f7264",
            "73616c74",
            4096,
            "3a4c406f77bad946ec51e09f8d808f749981ea32d61d9099a1800658bb45ddadd6c00260003c8dd5399629b63f052f40032707410d36fa1cbf2c5581fd70fc18",
        ),
        (
            "2.16.840.1.101.3.4.2.16",
            "This message will be PBMAC1 protected.",
            "70617373776f726450415353574f524470617373776f7264",
            "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
            4096,
            "4f3b091522f8068d6e90ed35d9c473f7bbcb6c6ef29b54afb5b11f04d986cab8b948e8332e81ac16005ccd318dbac17ffbe04a99f40390f2a31a942ade3aa5b7",
        ),
    ];

    #[test]
    fn test_pbmac1() {
        for (prf_oid, message, password_hex, salt_hex, iterations, expected_hex) in TEST_VECTORS {
            let password = tyst_encdec::hex::decode(&password_hex).unwrap();
            let salt = tyst_encdec::hex::decode(&salt_hex).unwrap();
            let prf = get_hmac(prf_oid);
            let mac = get_hmac(prf_oid);
            let actual_hex = Pbmac1::new(mac, Pbkdf2::new(prf))
                .pbmac(&password, &salt, *iterations, message.as_bytes())
                .to_hex();
            assert_eq!(&actual_hex, expected_hex);
        }
    }

    fn get_hmac(oid: &str) -> Box<dyn Mac> {
        match oid {
            "2.16.840.1.101.3.4.2.14" => Box::new(HmacMac::<136>::new(
                Box::new(DUMMY_REGISTRY.deref()),
                Box::new(Sha3Digest::new(256)),
            )),
            "2.16.840.1.101.3.4.2.15" => Box::new(HmacMac::<104>::new(
                Box::new(DUMMY_REGISTRY.deref()),
                Box::new(Sha3Digest::new(384)),
            )),
            "2.16.840.1.101.3.4.2.16" => Box::new(HmacMac::<72>::new(
                Box::new(DUMMY_REGISTRY.deref()),
                Box::new(Sha3Digest::new(512)),
            )),
            _ => panic!("Unsupported!"),
        }
    }
}
