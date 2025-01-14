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

//! External implementation of ECDSA from
//! [RustCrypto: Signatures](https://github.com/RustCrypto/signatures/).

use std::error::Error;

use tyst_traits::common::ConfinedObjectAsBytes;
use tyst_traits::common::ConfinementError;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::se::PrivateKey;
use tyst_traits::se::PublicKey;
use tyst_traits::se::SignatureEngine;
use tyst_traits::se::SignatureEngineParams;
use tyst_traits::CryptoRegistry;

// https://www.ietf.org/rfc/rfc5758.html#section-3.2
// iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA256 (2)
const OID_ISO_MEMBER_BODY_US_ANSI_X962_SIGNATURES_ECDSA_WITH_SHA2_SHA256: &str =
    "1.2.840.10045.4.3.2";
// iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA384 (2)
const OID_ISO_MEMBER_BODY_US_ANSI_X962_SIGNATURES_ECDSA_WITH_SHA2_SHA384: &str =
    "1.2.840.10045.4.3.3";

/// Factory for [EcdsaSignatureEngine].
pub struct EcdsaSignatureEngineFactory {
    provided: Vec<AlgorithmMetaData>,
}
impl Default for EcdsaSignatureEngineFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("ECDSA-with-SHA-256", env!("CARGO_PKG_NAME"))
                    .set_oid(OID_ISO_MEMBER_BODY_US_ANSI_X962_SIGNATURES_ECDSA_WITH_SHA2_SHA256),
                AlgorithmMetaData::new("ECDSA-with-SHA-384", env!("CARGO_PKG_NAME"))
                    .set_oid(OID_ISO_MEMBER_BODY_US_ANSI_X962_SIGNATURES_ECDSA_WITH_SHA2_SHA384),
            ],
        }
    }
}

impl Factory for EcdsaSignatureEngineFactory {
    type Type = dyn SignatureEngine;
    type Parameters = SignatureEngineParams;

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
            "ECDSA-with-SHA-256" => {
                Box::new(EcdsaSignatureEngine::new(algorithm_name, "secp256k1"))
            }
            "ECDSA-with-SHA-384" => Box::new(EcdsaSignatureEngine::new(algorithm_name, "P-384")),
            _ => panic!("Not implemented."),
        }
    }
}

/// Wrapper of external ECDSA implementation.
pub struct EcdsaSignatureEngine {
    algorithm_name: String,
    curve_name: String,
}

impl EcdsaSignatureEngine {
    #[doc(hidden)]
    /// Create a new instance
    fn new(algorithm_name: &str, curve_name: &str) -> Self {
        Self {
            algorithm_name: algorithm_name.to_string(),
            curve_name: curve_name.to_string(),
        }
    }
}

#[doc(hidden)]
enum EcdsaPrivateKeyHolder {
    P384 {
        private_key: p384::ecdsa::SigningKey,
    },
    K256 {
        private_key: k256::ecdsa::SigningKey,
    },
}
impl PrivateKey for EcdsaPrivateKeyHolder {}

impl ConfinedObjectAsBytes for EcdsaPrivateKeyHolder {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(match self {
            Self::K256 { private_key } => k256::pkcs8::EncodePrivateKey::to_pkcs8_der(private_key),
            Self::P384 { private_key } => p384::pkcs8::EncodePrivateKey::to_pkcs8_der(private_key),
        }
        .unwrap()
        .as_bytes()
        .to_vec())
    }
}
impl EcdsaPrivateKeyHolder {
    #[allow(clippy::borrowed_box)]
    fn from_curve(curve_name: &str, private_key: &Box<dyn PrivateKey>) -> Self {
        match curve_name {
            "secp256k1" => Self::K256 {
                private_key: k256::pkcs8::DecodePrivateKey::from_pkcs8_der(
                    &private_key.try_as_bytes().unwrap(),
                )
                .unwrap(),
            },
            "P-384" => Self::P384 {
                private_key: p384::pkcs8::DecodePrivateKey::from_pkcs8_der(
                    &private_key.try_as_bytes().unwrap(),
                )
                .unwrap(),
            },
            bad_curve => panic!("Unsupported curve '{bad_curve}'."),
        }
    }
}

#[doc(hidden)]
enum EcdsaPublicKeyHolder {
    K256 {
        public_key: k256::ecdsa::VerifyingKey,
    },
    P384 {
        public_key: p384::ecdsa::VerifyingKey,
    },
}

impl PublicKey for EcdsaPublicKeyHolder {
    fn try_as_spki(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(match self {
            Self::K256 { public_key } => {
                k256::pkcs8::EncodePublicKey::to_public_key_der(public_key)
            }
            Self::P384 { public_key } => {
                p384::pkcs8::EncodePublicKey::to_public_key_der(public_key)
            }
        }
        .unwrap()
        .as_bytes()
        .to_vec())
    }
}

impl EcdsaPublicKeyHolder {
    #[allow(clippy::borrowed_box)]
    fn from_curve(curve_name: &str, public_key: &Box<dyn PublicKey>) -> Self {
        match curve_name {
            "secp256k1" => Self::K256 {
                public_key: k256::pkcs8::DecodePublicKey::from_public_key_der(
                    &public_key.try_as_spki().unwrap(),
                )
                .unwrap(),
            },
            "P-384" => Self::P384 {
                public_key: p384::pkcs8::DecodePublicKey::from_public_key_der(
                    &public_key.try_as_spki().unwrap(),
                )
                .unwrap(),
            },
            bad_curve => panic!("Unsupported curve '{bad_curve}'."),
        }
    }
}

impl SignatureEngine for EcdsaSignatureEngine {
    fn get_algorithm_name(&self) -> String {
        self.algorithm_name.to_owned()
    }

    fn generate_key_pair(&mut self) -> (Box<dyn PublicKey>, Box<dyn PrivateKey>) {
        match self.curve_name.as_str() {
            "secp256k1" => {
                let mut rng = rand::thread_rng();
                let private_key = k256::ecdsa::SigningKey::random(&mut rng);
                let public_key = k256::ecdsa::VerifyingKey::from(&private_key);
                let priv_key = EcdsaPrivateKeyHolder::K256 { private_key };
                let pub_key = EcdsaPublicKeyHolder::K256 { public_key };
                (Box::new(pub_key), Box::new(priv_key))
            }
            "P-384" => {
                let mut rng = rand::thread_rng();
                let private_key = p384::ecdsa::SigningKey::random(&mut rng);
                let public_key = p384::ecdsa::VerifyingKey::from(&private_key);
                let priv_key = EcdsaPrivateKeyHolder::P384 { private_key };
                let pub_key = EcdsaPublicKeyHolder::P384 { public_key };
                (Box::new(pub_key), Box::new(priv_key))
            }
            bad_curve => panic!("Unsupported curve '{bad_curve}'."),
        }
    }

    fn sign(&mut self, private_key: &Box<dyn PrivateKey>, data: &[u8]) -> Option<Vec<u8>> {
        match self.algorithm_name.as_str() {
            "ECDSA-with-SHA-256" => {
                match EcdsaPrivateKeyHolder::from_curve(self.curve_name.as_str(), private_key) {
                    EcdsaPrivateKeyHolder::K256 { private_key } => {
                        let signature: k256::ecdsa::Signature =
                            k256::ecdsa::signature::Signer::sign(&private_key, data);
                        let bytes = k256::ecdsa::signature::SignatureEncoding::to_vec(&signature);
                        Some(bytes)
                    }
                    _ => panic!(
                        "Curve '{}' is not suitable for '{}'.",
                        self.curve_name, self.algorithm_name
                    ),
                }
            }
            "ECDSA-with-SHA-384" => {
                match EcdsaPrivateKeyHolder::from_curve(self.curve_name.as_str(), private_key) {
                    EcdsaPrivateKeyHolder::P384 { private_key } => {
                        let signature: p384::ecdsa::Signature =
                            p384::ecdsa::signature::Signer::sign(&private_key, data);
                        let bytes = p384::ecdsa::signature::SignatureEncoding::to_vec(&signature);
                        Some(bytes)
                    }
                    _ => panic!(
                        "Curve '{}' is not suitable for '{}'.",
                        self.curve_name, self.algorithm_name
                    ),
                }
            }
            bad_alg => {
                panic!("Unsupported signature algorithm '{bad_alg}'.");
            }
        }
    }

    fn verify(
        &mut self,
        public_key: &Box<dyn PublicKey>,
        signature: &[u8],
        message: &[u8],
    ) -> bool {
        match self.algorithm_name.as_str() {
            "ECDSA-with-SHA-256" => {
                match EcdsaPublicKeyHolder::from_curve(self.curve_name.as_str(), public_key) {
                    EcdsaPublicKeyHolder::K256 { public_key } => {
                        let signature = k256::ecdsa::Signature::try_from(signature).unwrap();
                        k256::ecdsa::signature::Verifier::verify(&public_key, message, &signature)
                            .is_ok()
                    }
                    _ => panic!(
                        "Curve '{}' is not suitable for '{}'.",
                        self.curve_name, self.algorithm_name
                    ),
                }
            }
            "ECDSA-with-SHA-384" => {
                match EcdsaPublicKeyHolder::from_curve(self.curve_name.as_str(), public_key) {
                    EcdsaPublicKeyHolder::P384 { public_key } => {
                        let signature = p384::ecdsa::Signature::try_from(signature).unwrap();
                        p384::ecdsa::signature::Verifier::verify(&public_key, message, &signature)
                            .is_ok()
                    }
                    _ => panic!(
                        "Curve '{}' is not suitable for '{}'.",
                        self.curve_name, self.algorithm_name
                    ),
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

    #[test]
    fn test_ecdsa_with_sha_384_and_p384() {
        crate::test::common::init_logger();
        let algorithm_name = "ECDSA-with-SHA-384";
        let curve_name = "P-384";
        let mut se = Box::new(EcdsaSignatureEngine::new(algorithm_name, curve_name));
        let (public_key, private_key) = se.generate_key_pair();
        let data = b"Hello legacy!";
        let signature = se.sign(&private_key, data).unwrap();
        let verified = se.verify(&public_key, &signature, data);
        assert_eq!(
            verified, true,
            "Signature algorithm '{algorithm_name}' using curve '{curve_name}' failed."
        )
    }
}
