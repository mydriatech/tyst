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

//! Psuedo-Random Number Generator (PRNG) traits and structs
//!
//! A PRNG is a.k.a Deterministic Random Bit Generator (DRBG) .

/// A source of (ideally) true random
pub trait EntropySource: Send {
    /** Prediction Resistance

    The insertion of fresh entropy at time T disallows determining the state at
    time T and T+i when any state prior to time T is known.
    */
    fn get_prediction_resistent(&self) -> bool;

    /// Return at least `bits` bits of entropy in the returned bytes.
    fn get_entropy(&mut self, bits: usize) -> Vec<u8>;

    // TODO: Get available entropy estimate?
}

/// Psuedo-Random Number Generator (PRNG) / Deterministic Random Bit Generator (DRBG)
pub trait SecureRandom: Send {
    /// Get human readable implementation identifier.
    fn get_algorithm_name(&self) -> String;

    /// Populate the whole slice `bytes` with random data.
    fn next_bytes(&mut self, bytes: &mut [u8]);

    /// Convinience method for returning a 64-bit random usigned number.
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; size_of::<u64>()];
        self.next_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }
}

/** Builder style Psuedo-Random Number Generator (PRNG) / Deterministic Random
Bit Generator (DRBG) parameters.

### Example

```
# use tyst_traits::prng::SecureRandomParams;
# let determinstic_testing_seed = vec![];
SecureRandomParams::default()
    .set_seed(determinstic_testing_seed);
```
*/
#[derive(Default)]
pub struct SecureRandomParams {
    seed: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl SecureRandomParams {
    /// Initialize the DRBG with a nonce, if the implementation supports it.
    pub fn set_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Get the DRBG initial seed.
    #[doc(hidden)]
    pub fn nonce(&self) -> &Option<Vec<u8>> {
        &self.nonce
    }

    /// Initialize the DRBG with a seed, if the implementation supports it.
    pub fn set_seed(mut self, seed: Vec<u8>) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Get the DRBG initial nonce.
    #[doc(hidden)]
    pub fn seed(&self) -> &Option<Vec<u8>> {
        &self.seed
    }
}
