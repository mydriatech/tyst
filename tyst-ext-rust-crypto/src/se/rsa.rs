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

//! External implementation of RSASSA from
//! [RustCrypto: Signatures](https://github.com/RustCrypto/signatures/).

use std::error::Error;

use rasn::prelude::*;
use rasn::types::Integer;
use rasn::AsnType;
use rasn::Encode;
use tyst_traits::common::ConfinedObjectAsBytes;
use tyst_traits::common::ConfinementError;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::se::PrivateKey;
use tyst_traits::se::PublicKey;
use tyst_traits::se::SignatureEngine;
use tyst_traits::se::SignatureEngineParams;
use tyst_traits::CryptoRegistry;

// {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha384WithRSAEncryption(12)}
//const OID_ISO_MEMBER_BODY_US_RSADSI_PKCS_PKCS_1_SHA384WITHRSAENCRYPTION: &str = "1.2.840.113549.1.1.12";
const OID_ISO_MEMBER_BODY_US_RSADSI_PKCS_PKCS_1_ID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";

/// Factory for [RsaSignatureEngine].
///
/// [SignatureEngineParams::set_strength] is used (ignoring PQC) to determine
/// modulus size.
pub struct RsaSignatureEngineFactory {
    provided: Vec<AlgorithmMetaData>,
}
impl Default for RsaSignatureEngineFactory {
    /*
    RSA-1024     80      79.999
    RSA-2048    112     110.118
    RSA-3072    128     131.970
    RSA-4096            149.731
    RSA-7680    192     196.253
    RSA-8192            201.701
    RSA-15360   256     262.619
    RSA-16384           269.752

    Security Strength Digital Signatures and Other Applications Requiring Collision Resistance
    ≤ 80    SHA-1
    112     SHA-224, SHA-512/224, SHA3-224
    128     SHA-256, SHA-512/256, SHA3-256
    192     SHA-384, SHA3-384
    ≥ 256   SHA-512, SHA3-512

    RSA-2048 → SHA*224  → Not very secure
    RSA-3072 → SHA*256
    RSA-4096 → SHA*384  (sha*256 is weaker)
    RSA-7680 → SHA*384
    RSA-15360 → SHA*512 → Not very practical

    https://cabforum.org/working-groups/code-signing/requirements/#71321-rsa still lists RSA-4096
        */
    fn default() -> Self {
        Self {
            provided: vec![
                // A descent selection of legacy algorithms?
                // Oked: CAB forum, CNSA 1.0. if length>=3072.
                // 1.2.840.113549.1.1.12
                //                AlgorithmMetaData::new("RSASSA-PKCS1-v1_5-SHA-384", env!("CARGO_PKG_NAME")),
                // 1.2.840.113549.1.1.10
                AlgorithmMetaData::new(
                    //"RSASSA-PSS-with-SHA-384-MGF1-with-SHA-384",
                    "RSASSA-PSS",
                    env!("CARGO_PKG_NAME"),
                )
                .set_oid(OID_ISO_MEMBER_BODY_US_RSADSI_PKCS_PKCS_1_ID_RSASSA_PSS),
            ],
        }
    }
}

impl Factory for RsaSignatureEngineFactory {
    type Type = dyn SignatureEngine;
    type Parameters = SignatureEngineParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        _registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        params: Self::Parameters,
    ) -> Box<Self::Type> {
        let modulus_len = match params.strength() {
            Some(bits) => {
                if bits > 192 {
                    log::warn!(
                        "Refusing to handle RSSSA ops with modulus larger than 8192 bits. Capping."
                    );
                    8192
                } else if bits > 150 {
                    7680
                } else if bits > 128 {
                    4096
                } else if bits == 128 {
                    3072
                } else {
                    log::warn!("Refusing to handle RSSSA ops with modulus smaller than 3072 bits. Capping.");
                    3072
                }
            }
            None => 3072,
        };
        #[allow(clippy::match_single_binding)]
        match algorithm_name {
            "RSASSA-PKCS1-v1_5-SHA-384" => {
                Box::new(RsaSignatureEngine::new(algorithm_name, modulus_len))
            }
            "RSASSA-PSS" => Box::new(RsaSignatureEngine::new(algorithm_name, modulus_len)),
            _ => panic!("Not implemented."),
        }
    }
}

/// Wrapper of external RSASSA implementation.
pub struct RsaSignatureEngine {
    algorithm_name: String,
    modulus_len: usize,
}

impl RsaSignatureEngine {
    #[doc(hidden)]
    /// Create a new instance
    fn new(algorithm_name: &str, modulus_len: usize) -> Self {
        Self {
            algorithm_name: algorithm_name.to_string(),
            modulus_len,
        }
    }
}

#[doc(hidden)]
struct RsaPrivateKeyHolder {
    rsa_private_key: rsa::RsaPrivateKey,
}

impl RsaPrivateKeyHolder {
    fn new(rsa_private_key: rsa::RsaPrivateKey) -> Self {
        Self { rsa_private_key }
    }
}

impl PrivateKey for RsaPrivateKeyHolder {}

impl ConfinedObjectAsBytes for RsaPrivateKeyHolder {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&self.rsa_private_key)
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    }
}
impl From<&dyn PrivateKey> for RsaPrivateKeyHolder {
    fn from(private_key: &dyn PrivateKey) -> Self {
        RsaPrivateKeyHolder::new(
            rsa::pkcs8::DecodePrivateKey::from_pkcs8_der(&private_key.try_as_bytes().unwrap())
                .unwrap(),
        )
    }
}

#[doc(hidden)]
struct RsaPublicKeyHolder {
    rsa_public_key: rsa::RsaPublicKey,
}

impl RsaPublicKeyHolder {
    fn new(rsa_public_key: rsa::RsaPublicKey) -> Self {
        Self { rsa_public_key }
    }
}

impl PublicKey for RsaPublicKeyHolder {
    fn try_as_spki(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(
            rsa::pkcs8::EncodePublicKey::to_public_key_der(&self.rsa_public_key)
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    }
}

impl From<&dyn PublicKey> for RsaPublicKeyHolder {
    fn from(public_key: &dyn PublicKey) -> Self {
        RsaPublicKeyHolder::new(
            rsa::pkcs8::DecodePublicKey::from_public_key_der(&public_key.try_as_spki().unwrap())
                .unwrap(),
        )
    }
}

/// As defined in [RFC8017 Appendix A.2.3](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3)
#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
struct RsassaPssParams {
    #[rasn(tag(explicit(0)), default)]
    pub hash_algorithm: rasn_pkix::AlgorithmIdentifier,
    #[rasn(tag(explicit(1)), default)]
    pub mask_gen_algorithm: rasn_pkix::AlgorithmIdentifier,
    /// Should match length of hash algo
    #[rasn(tag(explicit(2)), default)]
    pub salt_length: Integer,
    /// Must be 1
    #[rasn(tag(explicit(3)), default)]
    pub trailer_field: Integer,
}

impl SignatureEngine for RsaSignatureEngine {
    fn get_algorithm_name(&self) -> String {
        self.algorithm_name.to_owned()
    }

    fn get_algorithm_identifier(&self) -> Option<Vec<u8>> {
        let algorithm_identifier = match self.algorithm_name.as_str() {
            "RSASSA-PKCS1-v1_5-SHA-384" => {
                // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.2
                rasn_pkix::AlgorithmIdentifier {
                    algorithm: rasn::types::ObjectIdentifier::from(
                        rasn::types::Oid::new(&[1, 2, 840, 113549, 1, 1, 12]).unwrap(),
                    ),
                    parameters: None,
                }
            }
            // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3
            "RSASSA-PSS" => {
                let (hash_algorithm, salt_length) = if self.modulus_len >= 8192 {
                    // SHA-512
                    (
                        rasn_pkix::AlgorithmIdentifier {
                            algorithm: rasn::types::ObjectIdentifier::from(
                                rasn::types::Oid::new(&[2, 16, 840, 1, 101, 3, 4, 2, 3]).unwrap(),
                            ),
                            parameters: None,
                        },
                        64,
                    )
                } else {
                    // SHA-384
                    (
                        rasn_pkix::AlgorithmIdentifier {
                            algorithm: rasn::types::ObjectIdentifier::from(
                                rasn::types::Oid::new(&[2, 16, 840, 1, 101, 3, 4, 2, 2]).unwrap(),
                            ),
                            parameters: None,
                        },
                        48,
                    )
                };
                let rsassa_pss_params = RsassaPssParams {
                    hash_algorithm: hash_algorithm.clone(),
                    mask_gen_algorithm: rasn_pkix::AlgorithmIdentifier {
                        // id_mgf1 1.2.840.113549.
                        algorithm: rasn::types::ObjectIdentifier::from(
                            rasn::types::Oid::new(&[1, 2, 840, 113549, 1, 1, 8]).unwrap(),
                        ),
                        parameters: Some(Any::new(rasn::der::encode(&hash_algorithm).unwrap())),
                    },
                    salt_length: rasn::types::Integer::Primitive(salt_length),
                    trailer_field: rasn::types::Integer::Primitive(1),
                };
                rasn_pkix::AlgorithmIdentifier {
                    algorithm: rasn::types::ObjectIdentifier::from(
                        rasn::types::Oid::new(&[1, 2, 840, 113549, 1, 1, 10]).unwrap(),
                    ),
                    parameters: Some(Any::new(rasn::der::encode(&rsassa_pss_params).unwrap())),
                }
            }
            bad_alg => {
                panic!("Unsupported signature algorithm '{bad_alg}'.");
            }
        };
        rasn::der::encode(&algorithm_identifier).ok()
    }

    fn generate_key_pair(&mut self) -> (Box<dyn PublicKey>, Box<dyn PrivateKey>) {
        let mut rng = rand::thread_rng();
        let priv_key =
            rsa::RsaPrivateKey::new(&mut rng, self.modulus_len).expect("failed to generate a key");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let priv_key = RsaPrivateKeyHolder::new(priv_key);
        let pub_key = RsaPublicKeyHolder::new(pub_key);
        (Box::new(pub_key), Box::new(priv_key))
    }

    fn sign(&mut self, private_key: &dyn PrivateKey, data: &[u8]) -> Option<Vec<u8>> {
        let priv_key = RsaPrivateKeyHolder::from(private_key).rsa_private_key;
        match self.algorithm_name.as_str() {
            "RSASSA-PKCS1-v1_5-SHA-384" => {
                let signing_key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha384>::new(priv_key);
                let mut rng = rand::thread_rng();
                let signature =
                    rsa::signature::RandomizedSigner::sign_with_rng(&signing_key, &mut rng, data);
                let bytes = rsa::signature::SignatureEncoding::to_vec(&signature);
                Some(bytes)
            }
            "RSASSA-PSS" => {
                let mut rng = rand::thread_rng();
                let signature = if self.modulus_len >= 8192 {
                    let signing_key = rsa::pss::SigningKey::<rsa::sha2::Sha512>::new(priv_key);
                    rsa::signature::RandomizedSigner::sign_with_rng(&signing_key, &mut rng, data)
                } else {
                    // SHA-384 is strong enough compared to the modulus size
                    let signing_key = rsa::pss::SigningKey::<rsa::sha2::Sha384>::new(priv_key);
                    rsa::signature::RandomizedSigner::sign_with_rng(&signing_key, &mut rng, data)
                };
                let bytes = rsa::signature::SignatureEncoding::to_vec(&signature);
                Some(bytes)
            }
            bad_alg => {
                panic!("Unsupported signature algorithm '{bad_alg}'.");
            }
        }
    }

    fn verify(&mut self, public_key: &dyn PublicKey, signature: &[u8], message: &[u8]) -> bool {
        let pub_key = RsaPublicKeyHolder::from(public_key).rsa_public_key;
        match self.algorithm_name.as_str() {
            "RSASSA-PKCS1-v1_5-SHA-384" => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha384>::new(pub_key);
                let signature = rsa::pkcs1v15::Signature::try_from(signature).unwrap();
                rsa::signature::Verifier::verify(&verifying_key, message, &signature).is_ok()
            }
            "RSASSA-PSS" => {
                let signature = rsa::pss::Signature::try_from(signature).unwrap();
                if self.modulus_len >= 8192 {
                    let verifying_key = rsa::pss::VerifyingKey::<rsa::sha2::Sha512>::new(pub_key);
                    rsa::signature::Verifier::verify(&verifying_key, message, &signature).is_ok()
                } else {
                    let verifying_key = rsa::pss::VerifyingKey::<rsa::sha2::Sha384>::new(pub_key);
                    rsa::signature::Verifier::verify(&verifying_key, message, &signature).is_ok()
                }
            }
            bad_alg => {
                panic!("Unsupported signature algorithm '{bad_alg}'.");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Using 3072 in a unit test is mostly a waste of time
    //const TEST_MODULUS_LENGTH: usize = 3072;
    const TEST_MODULUS_LENGTH: usize = 1024;

    #[test]
    fn test_pkcs1_v1_5_sha_384() {
        crate::test::common::init_logger();
        let algorithm_name = "RSASSA-PKCS1-v1_5-SHA-384";
        let mut se = Box::new(RsaSignatureEngine::new(algorithm_name, TEST_MODULUS_LENGTH));
        let (public_key, private_key) = se.generate_key_pair();
        let data = b"Hello legacy!";
        let signature = se.sign(private_key.as_ref(), data).unwrap();
        let verified = se.verify(public_key.as_ref(), &signature, data);
        assert_eq!(
            verified, true,
            "RSA signature algorithm '{algorithm_name}' failed."
        )
    }

    #[test]
    fn test_pss_sha_384() {
        crate::test::common::init_logger();
        let algorithm_name = "RSASSA-PSS";
        let mut se = Box::new(RsaSignatureEngine::new(algorithm_name, TEST_MODULUS_LENGTH));
        let (public_key, private_key) = se.generate_key_pair();
        let data = b"Hello legacy!";
        let signature = se.sign(private_key.as_ref(), data).unwrap();
        let verified = se.verify(public_key.as_ref(), &signature, data);
        assert_eq!(
            verified, true,
            "RSA signature algorithm '{algorithm_name}' failed."
        )
    }
}
