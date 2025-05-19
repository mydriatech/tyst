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

//! ML-DSA private key.

use std::sync::Arc;
use tyst_traits::common::ConfinedObjectAsBytes;
use tyst_traits::common::ConfinementError;
use tyst_traits::se::PrivateKey;

use super::MldsaEngine;
use super::MldsaParams;
use super::MldsaPublicKey;

/// ML-DSA private key.
pub struct MldsaPrivateKey {
    #[doc(hidden)]
    params: Arc<MldsaParams>,
    #[doc(hidden)]
    rho: Vec<u8>,
    // Private
    #[doc(hidden)]
    k: Vec<u8>,
    #[doc(hidden)]
    tr: Vec<u8>,
    #[doc(hidden)]
    s1: Vec<u8>,
    #[doc(hidden)]
    s2: Vec<u8>,
    #[doc(hidden)]
    t0: Vec<u8>,
    //seed: Vec<u8>,
}

impl TryFrom<&dyn PrivateKey> for MldsaPrivateKey {
    type Error = String;

    fn try_from(private_key: &dyn PrivateKey) -> Result<Self, Self::Error> {
        // Ideally doing seomthing like this would be more efficient:
        //  if let Some(mldsa_private_key) = (&private_key as &dyn Any).downcast_ref::<MldsaPrivateKey>() {...
        // but https://github.com/rust-lang/rust/issues/65991 is still not stable
        let encoded = private_key.try_as_bytes().unwrap();
        // NIST FIPS 204 Table 2
        let algorithm_name = match encoded.len() {
            2560 => "ML-DSA-44",
            4032 => "ML-DSA-65",
            4896 => "ML-DSA-87",
            bad_size => {
                return Err(format!(
                    "Unknown algorithm for private key size of {bad_size} bytes."
                ));
            }
        };
        Ok(MldsaPrivateKey::new(
            &Arc::new(MldsaParams::by_name(algorithm_name)),
            &encoded,
        ))
    }
}

impl PrivateKey for MldsaPrivateKey {}

impl ConfinedObjectAsBytes for MldsaPrivateKey {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(Self::encode(
            &self.params,
            &self.rho,
            &self.k,
            &self.tr,
            &self.s1,
            &self.s2,
            &self.t0,
        ))
    }
}

#[allow(dead_code)]
impl MldsaPrivateKey {
    /// Return a new instance
    pub fn new(params: &Arc<MldsaParams>, priv_key: &[u8]) -> Self {
        let (o, rho) = Self::next_bytes(priv_key, 0, MldsaParams::SEED_BYTES);
        let (o, k) = Self::next_bytes(priv_key, o, MldsaParams::SEED_BYTES);
        let (o, tr) = Self::next_bytes(priv_key, o, MldsaParams::TR_BYTES);
        let (o, s1) = Self::next_bytes(priv_key, o, params.l * params.poly_eta_packed_bytes);
        let (o, s2) = Self::next_bytes(priv_key, o, params.k * params.poly_eta_packed_bytes);
        let (_, t0) = Self::next_bytes(priv_key, o, params.k * MldsaParams::POLY_T0_PACKED_BYTES);
        Self {
            params: Arc::clone(params),
            rho,
            k,
            tr,
            s1,
            s2,
            t0,
        }
    }

    #[doc(hidden)]
    /// Helper to split slice into uneven chunks
    fn next_bytes(source: &[u8], offset: usize, len: usize) -> (usize, Vec<u8>) {
        (offset + len, source[offset..offset + len].to_vec())
    }

    /// Return encoded version of parts that make up the private key.
    pub fn encode(
        params: &Arc<MldsaParams>,
        rho: &[u8],
        k: &[u8],
        tr: &[u8],
        s1: &[u8],
        s2: &[u8],
        t0: &[u8],
    ) -> Vec<u8> {
        let mut encoded = vec![
            0u8;
            MldsaParams::SEED_BYTES * 2
                + MldsaParams::TR_BYTES
                + params.l * params.poly_eta_packed_bytes
                + params.k * params.poly_eta_packed_bytes
                + params.k * MldsaParams::POLY_T0_PACKED_BYTES
        ];
        let mut o = 0;
        o += Self::write_at_offset(&mut encoded, o, rho);
        o += Self::write_at_offset(&mut encoded, o, k);
        o += Self::write_at_offset(&mut encoded, o, tr);
        o += Self::write_at_offset(&mut encoded, o, s1);
        o += Self::write_at_offset(&mut encoded, o, s2);
        Self::write_at_offset(&mut encoded, o, t0);
        encoded
    }

    #[doc(hidden)]
    /// Helper to merge uneven chunks into slice
    fn write_at_offset(buf: &mut [u8], offset: usize, source: &[u8]) -> usize {
        buf[offset..offset + source.len()].clone_from_slice(source);
        source.len()
    }

    /// Return the derived public key from this private key.
    pub fn get_public_key(&self) -> MldsaPublicKey {
        let t1_packed =
            MldsaEngine::derive_t1(&self.params, &self.rho, &self.s1, &self.s2, &self.t0);
        MldsaPublicKey::new(&MldsaPublicKey::encode(&self.rho, &t1_packed))
    }

    /// Common (public) part
    pub fn get_rho(&self) -> &[u8] {
        &self.rho
    }

    /// Private part
    pub fn get_k(&self) -> &[u8] {
        &self.k
    }

    /// Private part
    pub fn get_tr(&self) -> &[u8] {
        &self.tr
    }

    /// Private part
    pub fn get_s1(&self) -> &[u8] {
        &self.s1
    }

    /// Private part
    pub fn get_s2(&self) -> &[u8] {
        &self.s2
    }

    /// Private part
    pub fn get_t0(&self) -> &[u8] {
        &self.t0
    }
}
