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
use rasn::prelude::*;

/// Password-Based Message Authentication Code 1 (PBMAC1) paramets defined in
/// [RFC 8018 A.5](https://www.rfc-editor.org/rfc/rfc8018#appendix-A.5)
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Pbmac1Parameter {
    pub key_derivation_func: rasn_pkix::AlgorithmIdentifier,
    pub message_auth_scheme: rasn_pkix::AlgorithmIdentifier,
}

/// Password-Based Message Authentication Code 1 (PBMAC1) defined in
/// [RFC 8018 7.1](https://www.rfc-editor.org/rfc/rfc8018#section-7.1).
#[allow(dead_code)]
pub struct Pbmac1 {
    mac: Box<dyn Mac>,
    pbkdf2: Pbkdf2,
}

impl Pbmac1 {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-5(5) PBMAC1(14)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 5, 14];

    /// Return a new instance using the provided [Mac].
    pub fn new(mac: Box<dyn Mac>, pbkdf2: Pbkdf2) -> Self {
        Self { mac, pbkdf2 }
    }

    /// Return a new instance from the AlgorithmIdentifier which includes MAC, salt, c, dk_len and PRF algorithm.
    pub fn from_algorithm_identifier(
        crypto_registry_instance: &dyn tyst_traits::CryptoRegistry,
        algorithm_identifier: &[u8],
    ) -> Option<Self> {
        let algorithm_identifier =
            rasn::der::decode::<rasn_pkix::AlgorithmIdentifier>(algorithm_identifier).unwrap();
        if !algorithm_identifier.algorithm.to_vec().eq(&Self::OID) {
            log::debug!(
                "AlgorithmIdentifier OID was '{:?}'. Expected '{:?}'.",
                algorithm_identifier.algorithm.to_vec(),
                Self::OID
            );
            return None;
        }
        if let Some(parameters) = algorithm_identifier.parameters {
            let parameters =
                rasn::der::decode::<Pbmac1Parameter>(&parameters.into_bytes()).unwrap();
            if let Some(pbkdf2) = Pbkdf2::from_algorithm_identifier(
                crypto_registry_instance,
                &rasn::der::encode(&parameters.key_derivation_func).unwrap(),
            ) {
                if let Some(mac) =
                    crypto_registry_instance
                        .macs()
                        .by_oid(&tyst_encdec::oid::as_string(
                            &parameters.message_auth_scheme.algorithm,
                        ))
                {
                    return Some(Self::new(mac, pbkdf2));
                } else {
                    log::debug!(
                        "PBMAC1 parameters specify an unknown/unsupported MAC OID: {:?}",
                        parameters.message_auth_scheme.algorithm.to_vec()
                    );
                }
            } else {
                log::debug!("This implementation of PBMAC1 requires PBKDF2.");
            }
        } else {
            log::debug!("PBMAC1 parameters are required.");
        }
        None
    }

    /// Get human readable implementation identifier.
    pub fn get_algorithm_name(&self) -> String {
        "PBMAC1".to_string()
    }

    /// Get DER encoded `AlgorithmIdentifier`
    pub fn get_algorithm_identifier(&self) -> Vec<u8> {
        let key_derivation_func = rasn::der::decode::<rasn_pkix::AlgorithmIdentifier>(
            &self.pbkdf2.get_algorithm_identifier(),
        )
        .unwrap();
        let message_auth_scheme = rasn::der::decode::<rasn_pkix::AlgorithmIdentifier>(
            &self.mac.get_algorithm_identifier().unwrap(),
        )
        .unwrap();
        rasn::der::encode(&rasn_pkix::AlgorithmIdentifier {
            algorithm: rasn::types::ObjectIdentifier::new_unchecked(Self::OID.to_vec().into()),
            parameters: Some(rasn::types::Any::new(
                rasn::der::encode(&Pbmac1Parameter {
                    key_derivation_func,
                    message_auth_scheme,
                })
                .unwrap(),
            )),
        })
        .unwrap()
    }

    /// Create password based MAC.
    pub fn pbmac(&mut self, password: &[u8], message: &[u8]) -> Vec<u8> {
        let dk = self.pbkdf2.derive_key(password);
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

    const TEST_VECTORS: &[(&str, &str, &str, &str, usize, &str)] = &[
        // Generated with the BC implementation patched with https://github.com/bcgit/bc-java/pull/2070
        (
            "2.16.840.1.101.3.4.2.16",
            "This message will be PBMAC1 protected.",
            "666f6f626172313233",
            "612073616c742073616c74792073616c74792073616c74792073616c74792073616c74792073616c74792073616c74792073616c74792073616c742d73616c74",
            1024,
            "3a504246da1a069fecfd5811688fcc9f1d2b9017bf56821244eb5231712e7629678d614e68e6ef4d14954bbeda0a04ed907257363c501b48bca7580877c1313e",
        ),
    ];

    #[test]
    fn test_pbmac1() {
        for (prf_oid, message, password_hex, salt_hex, iterations, expected_hex) in TEST_VECTORS {
            let password = tyst_encdec::hex::decode(&password_hex).unwrap();
            let message = message.as_bytes();
            let salt = tyst_encdec::hex::decode(&salt_hex).unwrap();
            let prf = get_hmac(prf_oid);
            let mac = get_hmac(prf_oid);
            let dk_len = salt.len();
            let actual_hex = Pbmac1::new(mac, Pbkdf2::new(&salt, *iterations, dk_len, prf))
                .pbmac(&password, &message)
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
