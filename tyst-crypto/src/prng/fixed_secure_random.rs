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

//! Mock PRNG implementation for providing deterministic data during testing.

use tyst_traits::CryptoRegistry;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::prng::SecureRandom;
use tyst_traits::prng::SecureRandomParams;

pub struct FixedSecureRandomFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Default for FixedSecureRandomFactory {
    fn default() -> Self {
        Self {
            provided: vec![AlgorithmMetaData::new("fixed", env!("CARGO_PKG_NAME"))],
        }
    }
}

impl Factory for FixedSecureRandomFactory {
    type Type = dyn SecureRandom;
    type Parameters = SecureRandomParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        _registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        params: Self::Parameters,
    ) -> Box<Self::Type> {
        if let Some(seed) = params.seed() {
            match algorithm_name {
                "fixed" => Box::new(FixedSecureRandom::new(seed)),
                _ => panic!("Not implemented."),
            }
        } else {
            panic!("A seed is required for this PRNG");
        }
    }
}

pub struct FixedSecureRandom {
    data: Vec<u8>,
    index: usize,
}

impl FixedSecureRandom {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            index: 0,
        }
    }
}

impl SecureRandom for FixedSecureRandom {
    fn get_algorithm_name(&self) -> String {
        "fixed".to_string()
    }

    fn next_bytes(&mut self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.data[self.index..self.index + bytes.len()]);
        self.index += bytes.len();
    }
}
