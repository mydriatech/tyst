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

mod digest {
    //! Message digest (hash) implementations
    pub mod keccak_digest;
    pub mod sha3_digest;
    pub mod shake_digest;
}
mod mac {
    //! Message authentication code (MAC) implementations
    pub mod hmac;
}
mod prng {
    //! Psuedo-Random Number Generator (PRNG) / Deterministic Random Bit Generator (DRBG) implementations
    #[cfg(test)]
    pub mod fixed_secure_random;
    pub mod os_entropy_source;
    pub mod sp_800_90a;
}
mod se {
    //! Signature Engine (SE) implementations
    pub mod ml_dsa;
}
#[cfg(test)]
pub mod test {
    pub mod common;
}
pub mod util;

use std::sync::Arc;
use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::Factory;
use tyst_traits::mac::Mac;
use tyst_traits::mac::MacParams;
use tyst_traits::prng::SecureRandom;
use tyst_traits::prng::SecureRandomParams;
use tyst_traits::se::SignatureEngine;
use tyst_traits::se::SignatureEngineParams;
use tyst_traits::CryptoBundle;

/// Standard collection of relevant crypto algorithm implementations.
#[derive(Default)]
pub struct StandardCryptoBundle {}

impl CryptoBundle for StandardCryptoBundle {
    fn provided_digests(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn Digest, Parameters = DigestParams>>> {
        vec![
            Arc::new(digest::keccak_digest::KeccakDigestFactory::default()),
            Arc::new(digest::sha3_digest::Sha3DigestFactory::default()),
            Arc::new(digest::shake_digest::ShakeDigestFactory::default()),
        ]
    }

    fn provided_macs(&self) -> Vec<Arc<dyn Factory<Type = dyn Mac, Parameters = MacParams>>> {
        vec![Arc::new(mac::hmac::HmacMacFactory::default())]
    }

    fn provided_prngs(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn SecureRandom, Parameters = SecureRandomParams>>> {
        #[allow(unused_mut)]
        let mut ret: Vec<
            Arc<dyn Factory<Type = dyn SecureRandom, Parameters = SecureRandomParams>>,
        > = vec![Arc::new(
            prng::sp_800_90a::Sp80090aSecureRandomFactory::default(),
        )];
        #[cfg(test)]
        ret.push(Arc::new(
            prng::fixed_secure_random::FixedSecureRandomFactory::default(),
        ));
        ret
    }

    fn provided_ses(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn SignatureEngine, Parameters = SignatureEngineParams>>> {
        vec![Arc::new(se::ml_dsa::MldsaSignatureEngineFactory::default())]
    }
}
