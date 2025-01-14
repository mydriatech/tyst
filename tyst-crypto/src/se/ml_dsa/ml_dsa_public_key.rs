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

//! ML-DSA public key.

use std::error::Error;

use tyst_traits::se::PublicKey;

use super::MldsaParams;

/// ML-DSA public key.
pub struct MldsaPublicKey {
    rho: Vec<u8>,
    t1: Vec<u8>,
}

const OID_ML_DSA_44: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 17];
const OID_ML_DSA_65: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 18];
const OID_ML_DSA_87: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 19];

impl TryFrom<&dyn PublicKey> for MldsaPublicKey {
    type Error = String;

    fn try_from(value: &dyn PublicKey) -> Result<Self, Self::Error> {
        let spki: rasn_pkix::SubjectPublicKeyInfo =
            rasn::der::decode(&value.try_as_spki().map_err(|e| e.to_string()).unwrap())
                .map_err(|e| e.to_string())
                .unwrap();
        let encoded = spki.subject_public_key.as_raw_slice();
        // Length check using NIST FIPS 204 Table 2
        match spki.algorithm.algorithm.to_vec().as_slice() {
            OID_ML_DSA_44 => {
                if encoded.len() != 1312 {
                    return Err(format!(
                        "Public key length for ML-DSA-44 should be {}, not {}.",
                        1312,
                        encoded.len(),
                    ));
                }
            }
            OID_ML_DSA_65 => {
                if encoded.len() != 1952 {
                    return Err(format!(
                        "Public key length for ML-DSA-44 should be {}, not {}.",
                        1952,
                        encoded.len(),
                    ));
                }
            }
            OID_ML_DSA_87 => {
                if encoded.len() != 2592 {
                    return Err(format!(
                        "Public key length for ML-DSA-44 should be {}, not {}.",
                        2592,
                        encoded.len(),
                    ));
                }
            }
            bad_oid => return Err(format!("Unknown algorithm {bad_oid:?} for public key.")),
        }
        Ok(MldsaPublicKey::new(encoded))
    }
}

impl PublicKey for MldsaPublicKey {
    fn try_as_spki(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let oid = match self.t1.len() / MldsaParams::POLY_T1_PACKED_BYTES {
            // Match MldsaParams.k
            4 => OID_ML_DSA_44,
            6 => OID_ML_DSA_65,
            8 => OID_ML_DSA_87,
            _ => panic!(),
        };
        rasn::der::encode(&rasn_pkix::SubjectPublicKeyInfo {
            algorithm: rasn_pkix::AlgorithmIdentifier {
                algorithm: rasn::types::ObjectIdentifier::new_unchecked(oid.into()),
                parameters: None,
            },
            subject_public_key: rasn::types::BitString::from_vec(Self::encode(&self.rho, &self.t1)),
        })
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

#[allow(dead_code)]
impl MldsaPublicKey {
    /// Return a new instance.
    pub fn new(pub_key: &[u8]) -> Self {
        Self {
            rho: pub_key[0..MldsaParams::SEED_BYTES].to_vec(),
            t1: pub_key[MldsaParams::SEED_BYTES..pub_key.len()].to_vec(),
        }
    }

    /// Return the public key as bytes.
    pub fn encode(rho: &[u8], t1: &[u8]) -> Vec<u8> {
        let mut pub_key = vec![0u8; MldsaParams::SEED_BYTES + t1.len()];
        pub_key[0..MldsaParams::SEED_BYTES].clone_from_slice(rho);
        pub_key[MldsaParams::SEED_BYTES..MldsaParams::SEED_BYTES + t1.len()].clone_from_slice(t1);
        pub_key
    }

    /// Common (public) part
    pub fn get_rho(&self) -> &[u8] {
        &self.rho
    }

    /// Public part t1 in packed format
    pub fn get_t1_packed(&self) -> &[u8] {
        &self.t1
    }
}
