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

//! Message Authentication Code (MAC) traits and structs

use crate::common::BasicConfinement;
use crate::common::ConfinedObjectAsBytes;
use crate::common::Confinement;
use crate::common::ConfinementError;

/// Message Authentication Code (MAC) key (secret)
pub trait MacKey: Sync + Send + ConfinedObjectAsBytes {
    /// Information about where the key material can be used.
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(BasicConfinement::Soft)
    }
}

#[doc(hidden)]
struct SoftMacKey {
    key_material: Vec<u8>,
}

impl ConfinedObjectAsBytes for SoftMacKey {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(self.key_material.clone())
    }
}

impl MacKey for SoftMacKey {}

/// Interpret as a [MacKey].
pub trait ToMacKey {
    /// Return the object as a [MacKey].
    fn to_mac_key(self) -> Box<dyn MacKey>;
}

impl ToMacKey for &[u8] {
    fn to_mac_key(self) -> Box<dyn MacKey> {
        Box::new(SoftMacKey {
            key_material: self.to_vec(),
        })
    }
}

impl ToMacKey for Vec<u8> {
    fn to_mac_key(self) -> Box<dyn MacKey> {
        Box::new(SoftMacKey { key_material: self })
    }
}

/// Message Authentication Code (MAC)
pub trait Mac: Send {
    /// Generate a new [MacKey] suitale for this algorithm.
    fn generate_key(&self) -> Box<dyn MacKey>;

    /// Initialize.
    ///
    /// Must be invoked before [`update()`](Self::update()) and [`finalize()`](Self::finalize()).
    #[allow(clippy::borrowed_box)]
    fn init(&mut self, key: &Box<dyn MacKey>);

    /// Ingest/absorb the `data` into the MAC.
    fn update(&mut self, data: &[u8]);

    /// Write the output state (the "MAC") to `out` and reset the instance.
    fn finalize(&mut self, out: &mut [u8]);

    /// Reset the instance.
    fn reset(&mut self);

    /// Get the output size of the MAC in bits.
    fn get_mac_size_bits(&self) -> usize;

    /// Get human readable implementation identifier.
    fn get_algorithm_name(&self) -> String;

    /// Convinience method for initializing, ingesting the provided data and
    /// returning the output state (MAC) in a single invocation.
    #[allow(clippy::borrowed_box)]
    fn mac(&mut self, key: &Box<dyn MacKey>, data: &[u8]) -> Vec<u8> {
        self.init(key);
        self.update(data);
        let mut out = vec![0u8; self.get_mac_size_bits() >> 3];
        self.finalize(&mut out);
        out
    }
}

/// Message Authentication Code (MAC) parameters
#[derive(Default)]
pub struct MacParams {}
