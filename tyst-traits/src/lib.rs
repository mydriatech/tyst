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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod common;
pub mod digest;
pub mod factory;
pub mod kdf;
pub mod kem;
pub mod mac;
pub mod prng;
pub mod se;

use self::digest::Digest;
use self::digest::DigestParams;
use self::factory::Factory;
use self::factory::FactoryRegistry;
use self::kdf::Kdf;
use self::kdf::KdfParams;
use self::kem::Kem;
use self::kem::KemParams;
use self::mac::Mac;
use self::mac::MacParams;
use self::prng::SecureRandom;
use self::prng::SecureRandomParams;
use self::se::SignatureEngine;
use self::se::SignatureEngineParams;
use std::sync::Arc;

/** Implemented by provider crate to enable discovery of implemented algorithms.

All methods are optional to implement.
 */
pub trait CryptoBundle: Sync + Send {
    /// Return registry of Message Digest (hash) algorithm factories.
    fn provided_digests(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn Digest, Parameters = DigestParams>>> {
        vec![]
    }

    /// Return registry of Key Derivation Function (KDF) algorithm factories.
    fn provided_kdfs(&self) -> Vec<Arc<dyn Factory<Type = dyn Kdf, Parameters = KdfParams>>> {
        vec![]
    }

    /// Return registry of Key Encapsulation Mechanism (KEM) algorithm factories.
    fn provided_kems(&self) -> Vec<Arc<dyn Factory<Type = dyn Kem, Parameters = KemParams>>> {
        vec![]
    }

    /// Return registry of Message Authentication Code (MAC) algorithm factories.
    fn provided_macs(&self) -> Vec<Arc<dyn Factory<Type = dyn Mac, Parameters = MacParams>>> {
        vec![]
    }

    /// Return registry of Psuedo-Random Number Generator (PRNG) a.k.a.
    /// Deterministic Random Bit Generator (DRBG) algorithm factories.
    fn provided_prngs(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn SecureRandom, Parameters = SecureRandomParams>>> {
        vec![]
    }

    /// Return registry of Signature Engine (SE) algorithm factories.
    fn provided_ses(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn SignatureEngine, Parameters = SignatureEngineParams>>> {
        vec![]
    }
}

/// A registry can implement this trait to enable discovery of available algorithm implementions.
pub trait CryptoRegistry: Sync + Send {
    /// Return Message Digest (hash) algorithm factories provided by this bundle.
    fn digests(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Digest, Parameters = DigestParams>>
    {
        panic!("No Message Digest is provided by this implementation.")
    }

    /// Return Key Derivation Function (KDF) algorithm factories provided by this bundle.
    fn kdfs(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Kdf, Parameters = KdfParams>> {
        panic!("No Key Derivation Function is provided by this implementation.")
    }

    /// Return Key Encapsulation Mechanism (KEM) algorithm factories provided by this bundle.
    fn kems(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Kem, Parameters = KemParams>> {
        panic!("No Key Encapsulation Mechanism is provided by this implementation.")
    }

    /// Return Message Authentication Code (MAC) algorithm factories provided by this bundle.
    fn macs(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Mac, Parameters = MacParams>> {
        panic!("No Message Authentication Code is provided by this implementation.")
    }

    /// Return Psuedo-Random Number Generator (PRNG) a.k.a. Deterministic Random
    /// Bit Generator (DRBG) algorithm factories provided by this bundle.
    fn prngs(
        &self,
    ) -> &dyn FactoryRegistry<
        Fact = dyn Factory<Type = dyn SecureRandom, Parameters = SecureRandomParams>,
    > {
        panic!("No Psuedo-Random Number Generator is provided by this implementation.")
    }

    /// Fill the `target` slice with random from `dyn SecureRandom` instance
    /// using the requested `algorithm_name`.
    /// If no `algorithm_name` is provided, a cryptographically strong one will
    /// be choosen.
    #[allow(unused_variables)]
    fn prng_fill_with_random(&self, algorithm_name: Option<&str>, target: &mut [u8]) {
        panic!("No Psuedo-Random Number Generator instance is provided by this implementation.")
    }

    /// Return Signature Engine (SE) algorithm factories provided by this bundle.
    fn ses(
        &self,
    ) -> &dyn FactoryRegistry<
        Fact = dyn Factory<Type = dyn SignatureEngine, Parameters = SignatureEngineParams>,
    > {
        panic!("No Signature Engine is provided by this implementation.")
    }
}
