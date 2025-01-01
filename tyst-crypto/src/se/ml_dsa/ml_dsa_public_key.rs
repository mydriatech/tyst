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

use tyst_traits::common::ConfinedObjectAsBytes;
use tyst_traits::common::ConfinementError;
use tyst_traits::se::PublicKey;

use super::MldsaParams;

/// ML-DSA public key.
pub struct MldsaPublicKey {
    rho: Vec<u8>,
    t1: Vec<u8>,
}

impl TryFrom<&dyn PublicKey> for MldsaPublicKey {
    type Error = String;

    fn try_from(value: &dyn PublicKey) -> Result<Self, Self::Error> {
        let encoded = value.try_as_bytes().unwrap();
        // NIST FIPS 204 Table 2
        let _algorithm_name = match encoded.len() {
            1312 => "ML-DSA-44",
            1952 => "ML-DSA-65",
            2592 => "ML-DSA-87",
            bad_size => {
                return Err(format!(
                    "Unknown algorithm for public key size of {bad_size} bytes."
                ))
            }
        };
        Ok(MldsaPublicKey::new(&encoded))
    }
}

impl PublicKey for MldsaPublicKey {}

impl ConfinedObjectAsBytes for MldsaPublicKey {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(Self::encode(&self.rho, &self.t1))
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
