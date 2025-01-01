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

//! Entropy source implementation that takes "entropy" from the underlying
//! Operating System (OS) random source.

use tyst_traits::prng::EntropySource;

/// Entropy source that takes "entropy" from the underlying OS random source.
#[derive(Default)]
pub struct OsEntropySource {}

impl EntropySource for OsEntropySource {
    fn get_prediction_resistent(&self) -> bool {
        // We cannot be sure it is predection resistant.
        // This probably depends on the entropy quality used to feed the OS
        // PRNG.
        false
    }

    fn get_entropy(&mut self, minimum_bits: usize) -> Vec<u8> {
        // Round up, so we have at least the requested number of bits
        let mut dest = vec![0u8; (minimum_bits + 7) >> 3];
        if let Err(e) = getrandom::getrandom(&mut dest) {
            panic!("Failed to get sufficient entropy: {e:?}");
        }
        dest
    }
}
