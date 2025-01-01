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

mod factory_registry;

#[cfg(test)]
pub mod test {
    pub mod common;
}
#[cfg(test)]
mod tests {
    mod test_tests;
}

use self::factory_registry::FactoryRegistryImpl;
use crossbeam_skiplist::SkipMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use traits::digest::Digest;
use traits::digest::DigestParams;
use traits::factory::Factory;
use traits::factory::FactoryRegistry;
use traits::kem::Kem;
use traits::kem::KemParams;
use traits::mac::Mac;
use traits::mac::MacParams;
use traits::prng::SecureRandom;
use traits::prng::SecureRandomParams;
use traits::se::SignatureEngine;
use traits::se::SignatureEngineParams;
use traits::CryptoBundle;
use traits::CryptoRegistry;
pub use tyst_encdec as encdec;
pub use tyst_traits as traits;

#[doc(hidden)]
static INSTANCE: LazyLock<Tyst> = LazyLock::new(Tyst::default);

#[doc(hidden)]
fn instance() -> &'static Tyst {
    INSTANCE.deref()
}

/** Cryptographic provider registry.

Singleton factory registry for all cryptographic algorithms implementations.
 */
pub struct Tyst {
    /// Message digest (hash) factories
    digests: FactoryRegistryImpl<dyn Factory<Type = dyn Digest, Parameters = DigestParams>>,
    /// Key Encapsulation Mechanism (KEM) factories
    kems: FactoryRegistryImpl<dyn Factory<Type = dyn Kem, Parameters = KemParams>>,
    /// Message Authentication Code (MAC) factories
    macs: FactoryRegistryImpl<dyn Factory<Type = dyn Mac, Parameters = MacParams>>,
    /// Psuedo-Random Number Generators (PRNG) a.k.a. Determinsitc Random Bit Generators (DRBG) factories
    prngs:
        FactoryRegistryImpl<dyn Factory<Type = dyn SecureRandom, Parameters = SecureRandomParams>>,
    /// Signature Engine (SE) factories
    ses: FactoryRegistryImpl<
        dyn Factory<Type = dyn SignatureEngine, Parameters = SignatureEngineParams>,
    >,
    /// Determinsitc Random Bit Generator (DRBG) instances
    drbg_instance: SkipMap<String, Arc<Mutex<Box<dyn SecureRandom>>>>,
}

impl Default for Tyst {
    fn default() -> Self {
        let ret = Self {
            digests: FactoryRegistryImpl::default(),
            kems: FactoryRegistryImpl::default(),
            macs: FactoryRegistryImpl::default(),
            prngs: FactoryRegistryImpl::default(),
            ses: FactoryRegistryImpl::default(),
            drbg_instance: SkipMap::default(),
        };
        #[cfg(feature = "internal")]
        {
            log::debug!("Enabling internal crypto implementation.");
            ret.add_crypto_bundle_internal(Box::new(tyst_crypto::StandardCryptoBundle::default()));
        }
        #[cfg(feature = "external")]
        {
            log::debug!("Enabling external crypto implementation.");
            ret.add_crypto_bundle_internal(Box::new(
                tyst_ext_rust_crypto::ExternalRustCryptoBundle::default(),
            ));
        }
        ret
    }
}
impl Tyst {
    #[doc(hidden)]
    /// Lazily create and return a mutex-protected instance of the requested DRBG
    fn prng_instance_mutex(
        &self,
        algorithm_name: Option<&str>,
    ) -> Arc<Mutex<Box<dyn SecureRandom>>> {
        let algorithm_name = algorithm_name.unwrap_or("HMAC-DRBG-SHA3-512");
        let entry = self
            .drbg_instance
            .get_or_insert_with(algorithm_name.to_string(), || {
                Arc::new(Mutex::new(self.prngs().by_name(algorithm_name).unwrap()))
            });
        Arc::clone(entry.value())
    }
}

impl CryptoRegistry for Tyst {
    fn digests(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Digest, Parameters = DigestParams>>
    {
        &self.digests
    }

    fn kems(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Kem, Parameters = KemParams>> {
        &self.kems
    }

    fn macs(
        &self,
    ) -> &dyn FactoryRegistry<Fact = dyn Factory<Type = dyn Mac, Parameters = MacParams>> {
        &self.macs
    }

    fn prngs(
        &self,
    ) -> &dyn FactoryRegistry<
        Fact = dyn Factory<Type = dyn SecureRandom, Parameters = SecureRandomParams>,
    > {
        &self.prngs
    }

    fn prng_fill_with_random(&self, algorithm_name: Option<&str>, target: &mut [u8]) {
        self.prng_instance_mutex(algorithm_name)
            .lock()
            .unwrap()
            .next_bytes(target);
    }

    fn ses(
        &self,
    ) -> &dyn FactoryRegistry<
        Fact = dyn Factory<Type = dyn SignatureEngine, Parameters = SignatureEngineParams>,
    > {
        &self.ses
    }
}

impl Tyst {
    /// Return the single instance of the crypto provider
    pub fn instance() -> Box<&'static dyn CryptoRegistry> {
        Box::new(instance())
    }

    /// Add additional algorithm implementations to the instance
    pub fn add_crypto_bundle(crypto_bundle: Box<dyn CryptoBundle>) {
        instance().add_crypto_bundle_internal(crypto_bundle);
    }

    #[doc(hidden)]
    fn add_crypto_bundle_internal(&self, crypto_bundle: Box<dyn CryptoBundle>) {
        for factory in crypto_bundle.provided_digests() {
            self.digests.register(factory);
        }
        for factory in crypto_bundle.provided_kems() {
            self.kems.register(factory);
        }
        for factory in crypto_bundle.provided_macs() {
            self.macs.register(factory);
        }
        for factory in crypto_bundle.provided_prngs() {
            self.prngs.register(factory);
        }
        for factory in crypto_bundle.provided_ses() {
            self.ses.register(factory);
        }
    }
}
