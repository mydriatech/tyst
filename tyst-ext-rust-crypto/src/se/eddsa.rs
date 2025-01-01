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

//! External implementation of EdDSA from
//! [RustCrypto: Signatures](https://github.com/RustCrypto/signatures/).
//!
//! EdDSA is defined in [RFC8032](https://www.rfc-editor.org/rfc/rfc8032).

use tyst_traits::common::ConfinedObjectAsBytes;
use tyst_traits::common::ConfinementError;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::se::PrivateKey;
use tyst_traits::se::PublicKey;
use tyst_traits::se::SignatureEngine;
use tyst_traits::se::SignatureEngineParams;
use tyst_traits::CryptoRegistry;

/// Factory for [EddsaSignatureEngine].
pub struct EddsaSignatureEngineFactory {
    provided: Vec<AlgorithmMetaData>,
}
impl Default for EddsaSignatureEngineFactory {
    fn default() -> Self {
        Self {
            provided: vec![AlgorithmMetaData::new(
                "EdDSA-Ed25519",
                env!("CARGO_PKG_NAME"),
            )],
        }
    }
}

impl Factory for EddsaSignatureEngineFactory {
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
            "EdDSA-Ed25519" => Box::new(EddsaSignatureEngine::new(algorithm_name)),
            _ => panic!("Not implemented."),
        }
    }
}

/// Wrapper of external EdDSA implementation.
pub struct EddsaSignatureEngine {
    algorithm_name: String,
}

impl EddsaSignatureEngine {
    #[doc(hidden)]
    /// Create a new instance
    fn new(algorithm_name: &str) -> Self {
        Self {
            algorithm_name: algorithm_name.to_string(),
        }
    }
}

#[doc(hidden)]
struct EddsaPrivateKeyHolder {
    private_key: ed25519_dalek::SigningKey,
}

impl EddsaPrivateKeyHolder {
    fn new(private_key: ed25519_dalek::SigningKey) -> Self {
        Self { private_key }
    }
}

impl PrivateKey for EddsaPrivateKeyHolder {}

impl ConfinedObjectAsBytes for EddsaPrivateKeyHolder {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(
            ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_der(&self.private_key)
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    }
}
impl From<&Box<dyn PrivateKey>> for EddsaPrivateKeyHolder {
    fn from(value: &Box<dyn PrivateKey>) -> Self {
        EddsaPrivateKeyHolder::new(
            ed25519_dalek::pkcs8::DecodePrivateKey::from_pkcs8_der(&value.try_as_bytes().unwrap())
                .unwrap(),
        )
    }
}

#[doc(hidden)]
struct EddsaPublicKeyHolder {
    public_key: ed25519_dalek::VerifyingKey,
}

impl EddsaPublicKeyHolder {
    fn new(public_key: ed25519_dalek::VerifyingKey) -> Self {
        Self { public_key }
    }
}

impl PublicKey for EddsaPublicKeyHolder {}

impl ConfinedObjectAsBytes for EddsaPublicKeyHolder {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(
            ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_der(&self.public_key)
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    }
}

impl From<&Box<dyn PublicKey>> for EddsaPublicKeyHolder {
    fn from(public_key: &Box<dyn PublicKey>) -> Self {
        EddsaPublicKeyHolder::new(
            ed25519_dalek::pkcs8::DecodePublicKey::from_public_key_der(
                &public_key.try_as_bytes().unwrap(),
            )
            .unwrap(),
        )
    }
}

impl SignatureEngine for EddsaSignatureEngine {
    fn get_algorithm_name(&self) -> String {
        self.algorithm_name.to_owned()
    }

    fn generate_key_pair(&mut self) -> (Box<dyn PublicKey>, Box<dyn PrivateKey>) {
        let mut rng = rand::thread_rng();
        let private_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let public_key = private_key.verifying_key();
        let priv_key = EddsaPrivateKeyHolder::new(private_key);
        let pub_key = EddsaPublicKeyHolder::new(public_key);
        (Box::new(pub_key), Box::new(priv_key))
    }

    fn sign(&mut self, private_key: &Box<dyn PrivateKey>, data: &[u8]) -> Option<Vec<u8>> {
        match self.algorithm_name.as_str() {
            "EdDSA-Ed25519" => {
                let priv_key = EddsaPrivateKeyHolder::from(private_key).private_key;
                let signature = ed25519_dalek::Signer::sign(&priv_key, data);
                let bytes = ed25519_dalek::ed25519::SignatureEncoding::to_vec(&signature);
                Some(bytes)
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
            "EdDSA-Ed25519" => {
                let pub_key = EddsaPublicKeyHolder::from(public_key).public_key;
                let signature = ed25519_dalek::ed25519::Signature::try_from(signature).unwrap();
                rsa::signature::Verifier::verify(&pub_key, message, &signature).is_ok()
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
    fn test_eddsa_ed25519() {
        crate::test::common::init_logger();
        let algorithm_name = "EdDSA-Ed25519";
        let mut se = Box::new(EddsaSignatureEngine::new(algorithm_name));
        let (public_key, private_key) = se.generate_key_pair();
        let data = b"Hello legacy!";
        let signature = se.sign(&private_key, data).unwrap();
        let verified = se.verify(&public_key, &signature, data);
        assert_eq!(
            verified, true,
            "Signature algorithm '{algorithm_name}' failed."
        )
    }
}
