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

//! NIST SP 800-90A implementation of the HMAC-DRBG-SHA3 Deterministic Random
//! Bit Generators (DRBGs)

use super::Drbg;
use tyst_traits::mac::{Mac, ToMacKey};
use tyst_traits::prng::EntropySource;

/** NIST SP 800-90A implementation of the HMAC-DRBG-SHA3 Deterministic Random
Bit Generators (DRBGs).

The generator is seeded with `3*max_security_strength/2` as recommended in
NIST SP 800 90C 2.6.12.
*/
pub struct HmacDrbd {
    entropy_source: Box<dyn EntropySource>,
    k: Vec<u8>,
    v: Vec<u8>,
    mac: Box<dyn Mac>,
    reseed_counter: u64,
    max_security_strength: usize,
}

impl HmacDrbd {
    const RESEED_MAX: u64 = 1 << (48 - 1);
    const MAX_BITS_REQUEST: usize = 1 << (19 - 1);

    /// Return a new instance
    pub fn new(
        mut entropy_source: Box<dyn EntropySource>,
        mac: Box<dyn Mac>,
        nonce: &Option<Vec<u8>>,
    ) -> Self {
        // NIST SP 800-57 Part 1 Rev. 5, Table 3 for HMAC
        let max_security_strength = match mac.get_algorithm_name().as_str() {
            "HMAC-SHA3-224" => 192,
            "HMAC-SHA3-256" => 256,
            "HMAC-SHA3-384" => 256,
            "HMAC-SHA3-512" => 256,
            _ => panic!("Unsupported HMAC algorithm."),
        };
        // NIST SP 800 90C 2.6.12 recommends seeding with "3s/2"
        let mut entropy = entropy_source.get_entropy(3 * max_security_strength / 2);
        if let Some(nonce) = nonce {
            entropy.extend_from_slice(nonce);
        }
        let mut ret = Self {
            entropy_source,
            k: vec![0u8; mac.get_mac_size_bits() >> 3],
            v: vec![1u8; mac.get_mac_size_bits() >> 3],
            mac,
            reseed_counter: 1,
            max_security_strength,
        };
        ret.hmac_drbg_update(Some(&entropy));
        ret
    }

    /// Update the internal state of the HMAC, optionally with fresh seed material.
    fn hmac_drbg_update(&mut self, seed_material: Option<&[u8]>) {
        self.hmac_drbg_update_func(seed_material, 0x00);
        if seed_material.is_some() {
            self.hmac_drbg_update_func(seed_material, 0x01);
        }
    }

    #[doc(hidden)]
    fn hmac_drbg_update_func(&mut self, seed_material: Option<&[u8]>, v_value: u8) {
        self.mac.init(&self.k.clone().to_mac_key());
        self.mac.update(&self.v);
        self.mac.update(&[v_value]);
        if let Some(seed_material) = seed_material {
            self.mac.update(seed_material);
        }
        self.mac.finalize(&mut self.k);
        self.mac.init(&self.k.clone().to_mac_key());
        self.mac.update(&self.v);
        self.mac.finalize(&mut self.v);
    }
}

impl Drbg for HmacDrbd {
    fn get_prediction_resistant(&self) -> bool {
        self.entropy_source.get_prediction_resistent()
    }

    fn generate(
        &mut self,
        output: &mut [u8],
        mut additional_input: Option<&[u8]>,
    ) -> Option<usize> {
        let number_of_bits = output.len() >> 3;
        if number_of_bits > Self::MAX_BITS_REQUEST {
            panic!(
                "A maximum of {} bits per request is allowed.",
                Self::MAX_BITS_REQUEST
            )
        }
        if self.reseed_counter > Self::RESEED_MAX {
            return None;
        }
        if self.get_prediction_resistant() {
            self.reseed(additional_input);
            additional_input = None;
        }
        if additional_input.is_some() {
            self.hmac_drbg_update(additional_input);
        }
        let mut stack_allocated = [0u8; 32];
        let rv = if output.len() <= 32 {
            stack_allocated.as_mut_slice()
        } else {
            &mut vec![0u8; output.len()]
        };
        let m = output.len() / self.v.len();
        self.mac.init(&self.k.clone().to_mac_key());
        let v_len = self.v.len();
        let rv_len = output.len();
        for i in 0..m {
            self.mac.update(&self.v);
            self.mac.finalize(&mut self.v);
            rv[i * v_len..i * v_len + v_len].copy_from_slice(&self.v);
        }
        if m * v_len < rv_len {
            self.mac.update(&self.v);
            self.mac.finalize(&mut self.v);
            rv[m * v_len..rv_len].copy_from_slice(&self.v[0..rv_len - m * v_len]);
        }
        self.hmac_drbg_update(additional_input);
        self.reseed_counter += 1;
        output.copy_from_slice(&rv[0..rv_len]);
        Some(number_of_bits)
    }

    fn reseed(&mut self, additional_input: Option<&[u8]>) {
        let mut seed_material = self
            .entropy_source
            .get_entropy(3 * self.max_security_strength / 2);
        if let Some(additional_input) = additional_input {
            seed_material.extend_from_slice(additional_input);
        }
        self.hmac_drbg_update(Some(&seed_material));
        self.reseed_counter = 1;
    }
}
