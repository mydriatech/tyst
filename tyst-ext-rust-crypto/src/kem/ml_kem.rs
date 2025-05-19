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

//! External implementation of NIST FIPS 203 ML-KEM from
//! [RustCrypto: Key Encapsulation Mechanisms (KEMs)](https://github.com/RustCrypto/KEMs/).

use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use tyst_oids as oids;
use tyst_traits::CryptoRegistry;
use tyst_traits::common::ConfinedObjectAsBytes;
use tyst_traits::common::ConfinementError;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::kem::DecapsulationKey;
use tyst_traits::kem::EncapsulationKey;
use tyst_traits::kem::Kem;
use tyst_traits::kem::KemCipherText;
use tyst_traits::kem::KemParams;
use tyst_traits::kem::KemSharedSecret;

/// Factory for [MlkemKem].
pub struct MlkemKemFactory {
    provided: Vec<AlgorithmMetaData>,
}
impl Default for MlkemKemFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("ML-KEM-512", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(oids::kem::ML_KEM_512)),
                AlgorithmMetaData::new("ML-KEM-768", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(oids::kem::ML_KEM_768)),
                AlgorithmMetaData::new("ML-KEM-1024", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(oids::kem::ML_KEM_1024)),
            ],
        }
    }
}

impl Factory for MlkemKemFactory {
    type Type = dyn Kem;
    type Parameters = KemParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        _registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        _params: Self::Parameters,
    ) -> Box<Self::Type> {
        Box::new(MlkemKem::new(algorithm_name))
        //Box::new(MlkemKem::<ml_kem::MlKem512Params>::new())
    }
}

/// Wrapper of external ML-KEM implementation.
enum MlkemKem {
    #[doc(hidden)]
    MlKem512,
    #[doc(hidden)]
    MlKem768,
    #[doc(hidden)]
    MlKem1024,
}

#[doc(hidden)]
enum MlkemDecapsulationKey {
    MlKem512 {
        dk: Box<ml_kem::kem::DecapsulationKey<ml_kem::MlKem512Params>>,
    },
    MlKem768 {
        dk: Box<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>,
    },
    MlKem1024 {
        dk: Box<ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>>,
    },
}
impl DecapsulationKey for MlkemDecapsulationKey {}
impl ConfinedObjectAsBytes for MlkemDecapsulationKey {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        match self {
            Self::MlKem512 { dk } => Ok(dk.as_bytes().to_vec()),
            Self::MlKem768 { dk } => Ok(dk.as_bytes().to_vec()),
            Self::MlKem1024 { dk } => Ok(dk.as_bytes().to_vec()),
        }
    }
}
impl MlkemDecapsulationKey {
    pub fn from_trait_object(algorithm: &MlkemKem, value: &dyn DecapsulationKey) -> Self {
        match algorithm {
            MlkemKem::MlKem512 => {
                //let encoded = ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<ml_kem::MlKem512Params>>::from_iter(value.encoded().into_iter());
                MlkemDecapsulationKey::MlKem512 {
                    dk:
                        Box::new(
                            ml_kem::kem::DecapsulationKey::<ml_kem::MlKem512Params>::from_bytes(
                                &ml_kem::Encoded::<
                                    ml_kem::kem::DecapsulationKey<ml_kem::MlKem512Params>,
                                >::from_iter(
                                    value.try_as_bytes().unwrap()
                                ),
                            ),
                        ),
                }
            }
            MlkemKem::MlKem768 => {
                MlkemDecapsulationKey::MlKem768 {
                    dk:
                        Box::new(
                            ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
                                &ml_kem::Encoded::<
                                    ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
                                >::from_iter(
                                    value.try_as_bytes().unwrap()
                                ),
                            ),
                        ),
                }
            }
            MlkemKem::MlKem1024 => MlkemDecapsulationKey::MlKem1024 {
                dk:
                    Box::new(
                        ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(
                            &ml_kem::Encoded::<
                                ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>,
                            >::from_iter(value.try_as_bytes().unwrap()),
                        ),
                    ),
            },
        }
    }
}
impl MlkemDecapsulationKey {
    pub fn decapsulate(&self, cipher_text: &KemCipherText) -> Option<KemSharedSecret> {
        let cipher_text = cipher_text.as_bytes();
        match self {
            Self::MlKem512 { dk } => {
                //let ct = ml_kem::Ciphertext::<ml_kem::kem::Kem<ml_kem::MlKem512Params>>::from_iter(cipher_text.into_iter());
                ml_kem::kem::Decapsulate::decapsulate(
                    dk.as_ref(),
                    &ml_kem::Ciphertext::<ml_kem::kem::Kem<ml_kem::MlKem512Params>>::from_iter(
                        cipher_text,
                    ),
                )
                .ok()
                .map(|shared_secret| KemSharedSecret::from(shared_secret.to_vec()))
            }
            Self::MlKem768 { dk } => ml_kem::kem::Decapsulate::decapsulate(
                dk.as_ref(),
                &ml_kem::Ciphertext::<ml_kem::kem::Kem<ml_kem::MlKem768Params>>::from_iter(
                    cipher_text,
                ),
            )
            .ok()
            .map(|shared_secret| KemSharedSecret::from(shared_secret.to_vec())),
            Self::MlKem1024 { dk } => ml_kem::kem::Decapsulate::decapsulate(
                dk.as_ref(),
                &ml_kem::Ciphertext::<ml_kem::kem::Kem<ml_kem::MlKem1024Params>>::from_iter(
                    cipher_text,
                ),
            )
            .ok()
            .map(|shared_secret| KemSharedSecret::from(shared_secret.to_vec())),
        }
    }
}

#[doc(hidden)]
enum MlkemEncapsulationKey {
    MlKem512 {
        ek: Box<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>,
    },
    MlKem768 {
        ek: Box<ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>>,
    },
    MlKem1024 {
        ek: Box<ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>>,
    },
}
impl EncapsulationKey for MlkemEncapsulationKey {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::MlKem512 { ek } => ek.as_bytes().to_vec(),
            Self::MlKem768 { ek } => ek.as_bytes().to_vec(),
            Self::MlKem1024 { ek } => ek.as_bytes().to_vec(),
        }
    }
}
impl MlkemEncapsulationKey {
    pub fn from_trait_object(algorithm: &MlkemKem, value: &dyn EncapsulationKey) -> Self {
        match algorithm {
            MlkemKem::MlKem512 => {
                //let encoded = ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<ml_kem::MlKem512Params>>::from_iter(value.encoded().into_iter());
                MlkemEncapsulationKey::MlKem512 {
                    ek:
                        Box::new(
                            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(
                                &ml_kem::Encoded::<
                                    ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>,
                                >::from_iter(value.as_bytes()),
                            ),
                        ),
                }
            }
            MlkemKem::MlKem768 => {
                MlkemEncapsulationKey::MlKem768 {
                    ek:
                        Box::new(
                            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
                                &ml_kem::Encoded::<
                                    ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
                                >::from_iter(value.as_bytes()),
                            ),
                        ),
                }
            }
            MlkemKem::MlKem1024 => MlkemEncapsulationKey::MlKem1024 {
                ek:
                    Box::new(
                        ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(
                            &ml_kem::Encoded::<
                                ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>,
                            >::from_iter(value.as_bytes()),
                        ),
                    ),
            },
        }
    }

    fn encapsulate(&self) -> Option<(KemCipherText, KemSharedSecret)> {
        let mut rng = rand::thread_rng();
        match self {
            Self::MlKem512 { ek } => ml_kem::kem::Encapsulate::encapsulate(ek.as_ref(), &mut rng)
                .ok()
                .map(|(ct, shared_secret)| {
                    (
                        KemCipherText::from(ct.to_vec()),
                        KemSharedSecret::from(shared_secret.to_vec()),
                    )
                }),
            Self::MlKem768 { ek } => ml_kem::kem::Encapsulate::encapsulate(ek.as_ref(), &mut rng)
                .ok()
                .map(|(ct, shared_secret)| {
                    (
                        KemCipherText::from(ct.to_vec()),
                        KemSharedSecret::from(shared_secret.to_vec()),
                    )
                }),
            Self::MlKem1024 { ek } => ml_kem::kem::Encapsulate::encapsulate(ek.as_ref(), &mut rng)
                .ok()
                .map(|(ct, shared_secret)| {
                    (
                        KemCipherText::from(ct.to_vec()),
                        KemSharedSecret::from(shared_secret.to_vec()),
                    )
                }),
        }
    }
}

impl MlkemKem {
    #[doc(hidden)]
    /// Create a new instance
    fn new(algorithm_name: &str) -> Self {
        match algorithm_name {
            "ML-KEM-512" => MlkemKem::MlKem512,
            "ML-KEM-768" => MlkemKem::MlKem768,
            "ML-KEM-1024" => MlkemKem::MlKem1024,
            bad_algo => panic!("Unsupported algorithm '{bad_algo}'"),
        }
    }
}

impl Kem for MlkemKem {
    //fn get_algorithm_name(&self) -> String;
    fn key_gen(&mut self) -> (Box<dyn EncapsulationKey>, Box<dyn DecapsulationKey>) {
        let mut rng = rand::thread_rng();
        match self {
            Self::MlKem512 => {
                let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem512Params>::generate(&mut rng);
                (
                    Box::new(MlkemEncapsulationKey::MlKem512 { ek: Box::new(ek) }),
                    Box::new(MlkemDecapsulationKey::MlKem512 { dk: Box::new(dk) }),
                )
            }
            Self::MlKem768 => {
                let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut rng);
                (
                    Box::new(MlkemEncapsulationKey::MlKem768 { ek: Box::new(ek) }),
                    Box::new(MlkemDecapsulationKey::MlKem768 { dk: Box::new(dk) }),
                )
            }
            Self::MlKem1024 => {
                let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem1024Params>::generate(&mut rng);
                (
                    Box::new(MlkemEncapsulationKey::MlKem1024 { ek: Box::new(ek) }),
                    Box::new(MlkemDecapsulationKey::MlKem1024 { dk: Box::new(dk) }),
                )
            }
        }
    }
    fn encapsulate(
        &mut self,
        public_key: &dyn EncapsulationKey,
    ) -> Option<(KemCipherText, KemSharedSecret)> {
        MlkemEncapsulationKey::from_trait_object(self, public_key).encapsulate()
    }
    fn decapsulate(
        &mut self,
        private_key: &dyn DecapsulationKey,
        cipher_text: &KemCipherText,
    ) -> Option<KemSharedSecret> {
        MlkemDecapsulationKey::from_trait_object(self, private_key).decapsulate(cipher_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768() {
        crate::test::common::init_logger();
        let algorithm_name = "ML-KEM-768";
        let mut kem = Box::new(MlkemKem::new(algorithm_name));
        let (public_key, private_key) = kem.key_gen();
        let (ct, k_send) = kem.encapsulate(public_key.as_ref()).unwrap();
        let k_recv = kem.decapsulate(private_key.as_ref(), &ct).unwrap();
        assert_eq!(
            k_recv.as_bytes(),
            k_send.as_bytes(),
            "'{algorithm_name}' failed to generate the same shared secret."
        )
    }
}
