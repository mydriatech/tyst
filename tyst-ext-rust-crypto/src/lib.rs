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
    pub mod sha1;
    pub mod sha2;
}
mod kem {
    //! Key Encapsulation Mechanism (KEM) implementations
    pub mod ml_kem;
}
mod se {
    //! Signature Engine (SE) implementations
    pub mod ecdsa;
    pub mod eddsa;
    pub mod rsa;
}

#[cfg(test)]
pub mod test {
    //! Test utilities.
    pub mod common;
}

use std::sync::Arc;
use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::Factory;
use tyst_traits::kem::Kem;
use tyst_traits::kem::KemParams;
use tyst_traits::se::SignatureEngine;
use tyst_traits::se::SignatureEngineParams;
use tyst_traits::CryptoBundle;

/// [CryptoBundle] that provides externally implemented algorithms.
#[derive(Default)]
pub struct ExternalRustCryptoBundle {}

impl CryptoBundle for ExternalRustCryptoBundle {
    fn provided_digests(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn Digest, Parameters = DigestParams>>> {
        vec![
            Arc::new(digest::sha1::Sha1DigestFactory::default()),
            Arc::new(digest::sha2::Sha2DigestFactory::default()),
        ]
    }

    fn provided_kems(&self) -> Vec<Arc<dyn Factory<Type = dyn Kem, Parameters = KemParams>>> {
        vec![Arc::new(kem::ml_kem::MlkemKemFactory::default())]
    }

    fn provided_ses(
        &self,
    ) -> Vec<Arc<dyn Factory<Type = dyn SignatureEngine, Parameters = SignatureEngineParams>>> {
        vec![
            Arc::new(se::ecdsa::EcdsaSignatureEngineFactory::default()),
            Arc::new(se::eddsa::EddsaSignatureEngineFactory::default()),
            Arc::new(se::rsa::RsaSignatureEngineFactory::default()),
        ]
    }
}
