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

//! Signature Engine (SE) traits and structs

use std::error::Error;

use crate::common::BasicConfinement;
use crate::common::ConfinedObjectAsBytes;
use crate::common::Confinement;
use crate::common::ConfinementError;

/// Private key for asymmetric digital signatures (secret)
pub trait PrivateKey: Sync + Send + ConfinedObjectAsBytes {
    /// Information about where the key material can be used.
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(BasicConfinement::Soft)
    }
}

/// Public key for asymmetric digital signatures (public)
pub trait PublicKey: Sync + Send {
    /// Information about where the key material can be used.
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(BasicConfinement::Soft)
    }

    /// Get DER encoded `Subject Public Key Info` as defined in
    /// [RFC5280](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7).
    ///
    /// Fail if no OID exists for the type of key or if confinement prevents
    /// retrieval.
    fn try_as_spki(&self) -> Result<Vec<u8>, Box<dyn Error>>;

    /// Get raw key material as bytes
    fn try_as_raw(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let spki: rasn_pkix::SubjectPublicKeyInfo = rasn::der::decode(&self.try_as_spki()?)?;
        Ok(spki.subject_public_key.as_raw_slice().to_vec())
    }
}

#[doc(hidden)]
struct SoftPrivateKey {
    key_material: Vec<u8>,
}

impl PrivateKey for SoftPrivateKey {}

impl ConfinedObjectAsBytes for SoftPrivateKey {
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError> {
        Ok(self.key_material.clone())
    }
}

/// Interpret as a [PrivateKey].
pub trait ToPrivateKey {
    /// Return the object as a [PrivateKey].
    fn to_private_key(self) -> Box<dyn PrivateKey>;
}

impl ToPrivateKey for &[u8] {
    fn to_private_key(self) -> Box<dyn PrivateKey> {
        Box::new(SoftPrivateKey {
            key_material: self.to_vec(),
        })
    }
}

impl ToPrivateKey for Vec<u8> {
    fn to_private_key(self) -> Box<dyn PrivateKey> {
        Box::new(SoftPrivateKey { key_material: self })
    }
}

#[doc(hidden)]
struct SoftPublicKey {
    spki: Vec<u8>,
}

impl PublicKey for SoftPublicKey {
    fn try_as_spki(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.spki.clone())
    }
}

/// Interpret encoded SPKI as a [PublicKey].
pub trait ToPublicKey {
    /// Return the object as a [PublicKey].
    fn to_public_key(self) -> Box<dyn PublicKey>;
}

impl ToPublicKey for &[u8] {
    fn to_public_key(self) -> Box<dyn PublicKey> {
        Box::new(SoftPublicKey {
            spki: self.to_vec(),
        })
    }
}

impl ToPublicKey for Vec<u8> {
    fn to_public_key(self) -> Box<dyn PublicKey> {
        Box::new(SoftPublicKey { spki: self })
    }
}

/// Signature Engine (SE)
#[allow(clippy::borrowed_box)]
pub trait SignatureEngine: Send {
    /// Get human readable implementation identifier.
    fn get_algorithm_name(&self) -> String;

    /// Get DER encoded `AlgorithmIdentifier` as defined in
    /// [RFC5280](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2)
    /// if available for this signature algorithm.
    fn get_algorithm_identifier(&self) -> Option<Vec<u8>> {
        None
    }

    /// Generate a new asymmetric key pair and return the public and private key.
    fn generate_key_pair(&mut self) -> (Box<dyn PublicKey>, Box<dyn PrivateKey>);

    /// Sign the `message` using the [PrivateKey] and return the raw signatue.
    fn sign(&mut self, private_key: &Box<dyn PrivateKey>, message: &[u8]) -> Option<Vec<u8>>;

    /// Verify the `signature` of `message` using the [PublicKey] and return
    /// `true` if the signature was created with the corresponding [PrivateKey].
    fn verify(&mut self, public_key: &Box<dyn PublicKey>, signature: &[u8], message: &[u8])
        -> bool;
}

/** Builder style Signature Engine (SE) parameters.

### Example

```
# use tyst_traits::se::SignatureEngineParams;
SignatureEngineParams::default()
    .set_strength(256);
```
*/
#[derive(Default)]
pub struct SignatureEngineParams {
    strength: Option<usize>,
}

impl SignatureEngineParams {
    /// Request the estimated cryptographic strength
    pub fn set_strength(mut self, strength: usize) -> Self {
        self.strength = Some(strength);
        self
    }

    /// Get the estimated cryptographic strength
    #[doc(hidden)]
    pub fn strength(&self) -> Option<usize> {
        self.strength
    }
}
