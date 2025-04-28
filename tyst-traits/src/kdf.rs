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

//! Key Derivation Function (KDF) traits and structs

/// Key Derivation Function (KDF)
pub trait Kdf: Send {
    /// Get human readable implementation identifier.
    fn get_algorithm_name(&self) -> String;

    /// Derive a key using the provided input
    fn derive(&mut self, password: &[u8], salt: &[u8], n: usize, output: &mut [u8]);
}

/// Key Derivation Function (KDF) parameters
#[derive(Default)]
pub struct KdfParams {
    /// Psuedo random function OID
    prf: Option<Vec<u32>>,
}

impl KdfParams {
    /// Psuedo random function OID
    pub fn set_psuedo_random_function(mut self, oid: &[u32]) -> Self {
        self.prf = Some(oid.to_vec());
        self
    }

    #[doc(hidden)]
    pub fn psuedo_random_function(&self) -> Option<Vec<u32>> {
        self.prf.clone()
    }
}
