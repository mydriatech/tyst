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

//! Key Encapsulation Mechanism (KEM) traits and structs

use crate::common::BasicConfinement;
use crate::common::ConfinedObjectAsBytes;
use crate::common::Confinement;
use crate::common::ConfinementError;

/// KEM Decapsulation Key (secret)
pub trait DecapsulationKey: Sync + Send + ConfinedObjectAsBytes {
    /// Information about where the key material can be used.
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(BasicConfinement::Soft)
    }
}

#[doc(hidden)]
struct SoftDecapsulationKey {
    key_material: Vec<u8>,
}

impl ConfinedObjectAsBytes for SoftDecapsulationKey {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(self.key_material.clone())
    }
}

impl DecapsulationKey for SoftDecapsulationKey {}

/// Interpret as a [DecapsulationKey].
pub trait ToDecapsulationKey {
    /// Return the object as a [DecapsulationKey].
    fn to_decapsulation_key(self) -> Box<dyn DecapsulationKey>;
}

impl ToDecapsulationKey for &[u8] {
    fn to_decapsulation_key(self) -> Box<dyn DecapsulationKey> {
        Box::new(SoftDecapsulationKey {
            key_material: self.to_vec(),
        })
    }
}

impl ToDecapsulationKey for Vec<u8> {
    fn to_decapsulation_key(self) -> Box<dyn DecapsulationKey> {
        Box::new(SoftDecapsulationKey { key_material: self })
    }
}

// Is there any valid use-case for an encapsulation key to not be soft?

/// KEM Encapsulation Key (public)
pub trait EncapsulationKey: Sync + Send {
    /// Return the object as raw bytes
    fn as_bytes(&self) -> Vec<u8>;
}

#[doc(hidden)]
struct SoftEncapsulationKey {
    key_material: Vec<u8>,
}

impl EncapsulationKey for SoftEncapsulationKey {
    fn as_bytes(&self) -> Vec<u8> {
        self.key_material.clone()
    }
}

/// Interpret as a [EncapsulationKey].
pub trait ToEncapsulationKey {
    /// Return the object as a [DecapsulationKey].
    fn to_decapsulation_key(self) -> Box<dyn EncapsulationKey>;
}

impl ToEncapsulationKey for &[u8] {
    fn to_decapsulation_key(self) -> Box<dyn EncapsulationKey> {
        Box::new(SoftEncapsulationKey {
            key_material: self.to_vec(),
        })
    }
}

impl ToEncapsulationKey for Vec<u8> {
    fn to_decapsulation_key(self) -> Box<dyn EncapsulationKey> {
        Box::new(SoftEncapsulationKey { key_material: self })
    }
}

/// KEM Encapsulated shared secret cipher text (public)
pub struct KemCipherText(Vec<u8>);

impl From<Vec<u8>> for KemCipherText {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl KemCipherText {
    /// Return the object as raw bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// KEM Derived shared secret (secret)
pub struct KemSharedSecret(Vec<u8>);

impl From<Vec<u8>> for KemSharedSecret {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl KemSharedSecret {
    /// Return the object as raw bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Key Encapsulation Mechanism (KEM)
#[allow(clippy::borrowed_box)]
pub trait Kem: Send {
    /// Generate a new key pair
    fn key_gen(&mut self) -> (Box<dyn EncapsulationKey>, Box<dyn DecapsulationKey>);

    /// Generate a new shared secret, encapsulate the secret and return both versions.
    fn encapsulate(
        &mut self,
        public_key: &Box<dyn EncapsulationKey>,
    ) -> Option<(KemCipherText, KemSharedSecret)>;

    /// Derive the shared secret by decapsulating the encapsulated cipher text version.
    fn decapsulate(
        &mut self,
        private_key: &Box<dyn DecapsulationKey>,
        cipher_text: &KemCipherText,
    ) -> Option<KemSharedSecret>;
}

/// Key Encapsulation Mechanism (KEM) algorithm parameters
#[derive(Default)]
pub struct KemParams {}
