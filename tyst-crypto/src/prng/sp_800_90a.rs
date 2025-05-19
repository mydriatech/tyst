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

//! NIST SP 800-90A Deterministic Random Bit Generators (DRBGs)

mod hmac_drbd;

use crate::prng::os_entropy_source::OsEntropySource;
use hmac_drbd::HmacDrbd;
use tyst_oids as oids;
use tyst_traits::CryptoRegistry;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::prng::SecureRandom;
use tyst_traits::prng::SecureRandomParams;

/*
From https://pages.nist.gov/ACVP/draft-vassilev-acvp-drbg.html#supported_values

    DRBG Alg    Mode        DF     Max      Min     Max     Max     Max     Min     Max     Min
                                   Security Entropy Entropy Perso   Addl    Nonce   Nonce   returnedBits
                                   Strength Len     Len     String  String  Len     Len     Len

    (hashDRBG   "SHA3-224"  N/A     192     192     65536   65536   65536    96     65536   224)
    hmacDRBG    "SHA3-256"  N/A     256     256     65536   65536   65536   128     65536   256
    hmacDRBG    "SHA3-384"  N/A     256     256     65536   65536   65536   128     65536   384
    hmacDRBG    "SHA3-512"  N/A     256     256     65536   65536   65536   128     65536   512

    (hmacDRBG   "SHA3-224"  N/A     192     192     65536   65536   65536    96     65536   224)
    hmacDRBG    "SHA3-256"  N/A     256     256     65536   65536   65536   128     65536   256
    hmacDRBG    "SHA3-384"  N/A     256     256     65536   65536   65536   128     65536   384
    hmacDRBG    "SHA3-512"  N/A     256     256     65536   65536   65536   128     65536   512

From https://www.cyber.gc.ca/en/guidance/cryptographic-algorithms-unclassified-protected-protected-b-information-itsp40111
    and https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf
    "SHA3-224 should be phased out by the end of 2030."

Reading https://www.iacr.org/archive/eurocrypt2019/114760349/114760349.pdf
    It seems like HMAC-DRBG will provide "forward secrecy", while the others will not.

From https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90C.4pd.pdf 2.6.12
    At least 3s/2 bits of entropy will be required for construction of strength s. (e.g. 384 instead of 256)
    RBG2 provides forward secrecy. RBG2 and RBG1 seems to be the only realistic ones for software.
*/

/// Deterministic Random Bit Generator (DRBG)
trait Drbg: Send {
    //fn get_block_size_bits(&self) -> usize;

    /// Populate `output` with random data of the returned size.
    fn generate(&mut self, output: &mut [u8], additional_input: Option<&[u8]>) -> Option<usize>;

    /// Reseed the DRBG with fresh entropy from the underlying [tyst_traits::prng::EntropySource] and `additional_input`.
    fn reseed(&mut self, additional_input: Option<&[u8]>);

    /** Prediction Resistance

    The insertion of fresh entropy at time T disallows determining the state at
    time T and T+i when any state prior to time T is known.
    */
    fn get_prediction_resistant(&self) -> bool;
}

/// Factory for [Sp80090aSecureRandom].
pub struct Sp80090aSecureRandomFactory {
    provided: Vec<AlgorithmMetaData>,
}
impl Default for Sp80090aSecureRandomFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("HMAC-DRBG-SHA3-256", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("HMAC-DRBG-SHA3-384", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("HMAC-DRBG-SHA3-512", env!("CARGO_PKG_NAME")),
            ],
        }
    }
}

impl Factory for Sp80090aSecureRandomFactory {
    type Type = dyn SecureRandom;
    type Parameters = SecureRandomParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        params: Self::Parameters,
    ) -> Box<Self::Type> {
        if params.seed().is_some() {
            log::info!(
                "A seed was provided to the NIST SP 800-90A DRBG, but this was ignored. Use nonce instead."
            );
        }
        let nonce = params.nonce();
        match algorithm_name {
            "HMAC-DRBG-SHA3-256" => Box::new(Sp80090aSecureRandom::new(
                algorithm_name,
                Box::new(HmacDrbd::new(
                    Box::new(OsEntropySource::default()),
                    registry
                        .macs()
                        .by_oid(&tyst_encdec::oid::as_string(oids::mac::HMAC_SHA3_256))
                        .unwrap(),
                    nonce,
                )),
            )),
            "HMAC-DRBG-SHA3-384" => Box::new(Sp80090aSecureRandom::new(
                algorithm_name,
                Box::new(HmacDrbd::new(
                    Box::new(OsEntropySource::default()),
                    registry
                        .macs()
                        .by_oid(&tyst_encdec::oid::as_string(oids::mac::HMAC_SHA3_384))
                        .unwrap(),
                    nonce,
                )),
            )),
            "HMAC-DRBG-SHA3-512" => Box::new(Sp80090aSecureRandom::new(
                algorithm_name,
                Box::new(HmacDrbd::new(
                    Box::new(OsEntropySource::default()),
                    registry
                        .macs()
                        .by_oid(&tyst_encdec::oid::as_string(oids::mac::HMAC_SHA3_512))
                        .unwrap(),
                    nonce,
                )),
            )),
            _ => panic!("Not implemented."),
        }
    }
}

/// NIST SP 800-90A Deterministic Random Bit Generator (DRBG)
///
/// The HMAC-DRBG-SHA3 algorithms are implemented via [HmacDrbd].
pub struct Sp80090aSecureRandom {
    algorithm_name: String,
    drbg: Box<dyn Drbg>,
}

impl Sp80090aSecureRandom {
    #[doc(hidden)]
    /// Return a new instance.
    fn new(algorithm_name: &str, drbg: Box<dyn Drbg>) -> Self {
        Self {
            algorithm_name: algorithm_name.to_owned(),
            drbg,
        }
    }
}

impl SecureRandom for Sp80090aSecureRandom {
    fn get_algorithm_name(&self) -> String {
        self.algorithm_name.to_owned()
    }

    fn next_bytes(&mut self, bytes: &mut [u8]) {
        if self.drbg.generate(bytes, None).is_some() {
            // Reseed transparently if requied
            self.drbg.reseed(None);
            self.drbg.generate(bytes, None);
        }
    }
}
