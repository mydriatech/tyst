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

//! NIST FIPS 204 ML-DSA implementation

/*
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

    * Only implementing the hedged variant is sufficient to guarantee interoperability.
    * Implementations of ML-DSA shall ensure that any potentially sensitive intermediate data is
        destroyed as soon as it is no longer needed.
    * This standard makes use of the functions SHAKE256 and SHAKE128, as defined in FIPS 202

    Other implementations
    * https://github.com/open-quantum-safe/liboqs/tree/main/src/sig/ml_dsa (well documented)
    * https://github.com/bcgit/bc-java/tree/main/core/src/main/java/org/bouncycastle/pqc/crypto/mldsa
*/

mod ml_dsa_params;
mod ml_dsa_private_key;
mod ml_dsa_public_key;
mod packing;
mod poly;
mod poly_vec_k;
mod poly_vec_l;
mod poly_vec_matrix;
#[cfg(test)]
mod tests {
    mod ml_dsa_test;
}

pub use self::ml_dsa_params::MldsaParams;
pub use self::ml_dsa_private_key::MldsaPrivateKey;
pub use self::ml_dsa_public_key::MldsaPublicKey;
use self::poly::Poly;
use self::poly_vec_k::PolyVecK;
use self::poly_vec_l::PolyVecL;
use self::poly_vec_matrix::PolyVecMatrix;
use crate::digest::shake_digest::ShakeDigest;
use std::sync::Arc;
use tyst_traits::digest::Digest;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::prng::SecureRandom;
use tyst_traits::se::PrivateKey;
use tyst_traits::se::PublicKey;
use tyst_traits::se::SignatureEngine;
use tyst_traits::se::SignatureEngineParams;
use tyst_traits::CryptoRegistry;

/// Factory for the [MldsaEngine].
pub struct MldsaSignatureEngineFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl MldsaSignatureEngineFactory {
    /// `2.16.840.1.101.3.4.3.17`
    ///
    /// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3) ml-dsa-44(17)
    const OID_ML_DSA_44: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
    /// `2.16.840.1.101.3.4.3.18`
    ///
    /// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3) ml-dsa-65(18)
    const OID_ML_DSA_65: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
    /// `2.16.840.1.101.3.4.3.18`
    ///
    /// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3) ml-dsa-87(19)
    const OID_ML_DSA_87: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

    //  id-hash-ml-dsa-44-with-sha512(32)
    //  id-hash-ml-dsa-65-with-sha512(33)
    //  id-hash-ml-dsa-87-with-sha512(34)
}


impl Default for MldsaSignatureEngineFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("ML-DSA-44", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_ML_DSA_44)),
                AlgorithmMetaData::new("ML-DSA-65", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_ML_DSA_65)),
                AlgorithmMetaData::new("ML-DSA-87", env!("CARGO_PKG_NAME"))
                    .set_oid(&tyst_encdec::oid::as_string(Self::OID_ML_DSA_87)),
            ],
        }
    }
}

impl Factory for MldsaSignatureEngineFactory {
    type Type = dyn SignatureEngine;
    type Parameters = SignatureEngineParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        _params: Self::Parameters,
    ) -> Box<Self::Type> {
        /* NIST FIPS 204 3.6.1:
        "...RBG used shall have a security strength of at least 192 bits for
         ML-DSA-65 and 256 bits for ML-DSA-87. For ML-DSA-44, the RBG should
         have a security strength of at least 192 bits and shall have a security
         strength of at least 128 bits."
        */
        match algorithm_name {
            "ML-DSA-44" => Box::new(MldsaEngine::new(
                algorithm_name,
                registry.prngs().by_name("HMAC-DRBG-SHA3-256"),
            )),
            "ML-DSA-65" => Box::new(MldsaEngine::new(
                algorithm_name,
                registry.prngs().by_name("HMAC-DRBG-SHA3-384"),
            )),
            "ML-DSA-87" => Box::new(MldsaEngine::new(
                algorithm_name,
                registry.prngs().by_name("HMAC-DRBG-SHA3-512"),
            )),
            _ => panic!("Not implemented."),
        }
    }
}

/// ML-DSA Signature Engine implementation.
pub struct MldsaEngine {
    digest: Box<dyn Digest>,
    params: Arc<MldsaParams>,
    secure_random: Option<Box<dyn SecureRandom>>,
    algorithm_name: String,
}

impl SignatureEngine for MldsaEngine {
    fn get_algorithm_name(&self) -> String {
        self.algorithm_name.to_owned()
    }

    fn get_algorithm_identifier(&self) -> Option<Vec<u8>> {
        let algorithm = match self.algorithm_name.as_str() {
            "ML-DSA-44" => rasn::types::ObjectIdentifier::from(
                rasn::types::Oid::new(MldsaSignatureEngineFactory::OID_ML_DSA_44).unwrap(),
            ),
            "ML-DSA-65" => rasn::types::ObjectIdentifier::from(
                rasn::types::Oid::new(MldsaSignatureEngineFactory::OID_ML_DSA_65).unwrap(),
            ),
            "ML-DSA-87" => rasn::types::ObjectIdentifier::from(
                rasn::types::Oid::new(MldsaSignatureEngineFactory::OID_ML_DSA_87).unwrap(),
            ),
            bad_alg => {
                panic!("Unsupported signature algorithm '{bad_alg}'.");
            }
        };
        let algorithm_identifier = rasn_pkix::AlgorithmIdentifier {
            algorithm,
            // https://www.rfc-editor.org/rfc/rfc8410#section-6
            parameters: Some(rasn::types::Any::new(rasn::der::encode(&()).unwrap())),
        };
        rasn::der::encode(&algorithm_identifier).ok()
    }

    fn generate_key_pair(&mut self) -> (Box<dyn PublicKey>, Box<dyn PrivateKey>) {
        let (pub_key, priv_key) = self.generate_key_pair_with_secure_random();
        (Box::new(pub_key), Box::new(priv_key))
    }

    fn sign(&mut self, private_key: &dyn PrivateKey, data: &[u8]) -> Option<Vec<u8>> {
        match MldsaPrivateKey::try_from(private_key) {
            Err(e) => {
                log::info!("Failed to parse private key: {e:?}");
                None
            }
            Ok(mldsa_private_key) => {
                let mut rnd = [0u8; 32];
                if let Some(secure_random) = &mut self.secure_random {
                    secure_random.next_bytes(&mut rnd);
                }
                self.init_and_sign_internal(
                    mldsa_private_key.get_tr(),
                    false,
                    None,
                    data,
                    mldsa_private_key.get_rho(),
                    mldsa_private_key.get_k(),
                    mldsa_private_key.get_t0(),
                    mldsa_private_key.get_s1(),
                    mldsa_private_key.get_s2(),
                    &rnd,
                )
            }
        }
    }

    fn verify(&mut self, public_key: &dyn PublicKey, signature: &[u8], message: &[u8]) -> bool {
        match MldsaPublicKey::try_from(public_key) {
            Err(e) => {
                log::info!("Failed to parse public key: {e:?}");
                false
            }
            Ok(mldsa_public_key) => {
                self.init_verify(
                    mldsa_public_key.get_rho(),
                    mldsa_public_key.get_t1_packed(),
                    false,
                    None,
                );
                self.verify_internal_msg(
                    signature,
                    message,
                    mldsa_public_key.get_rho(),
                    mldsa_public_key.get_t1_packed(),
                )
            }
        }
    }
}

impl MldsaEngine {
    /// Return a new instance.
    pub fn new(algorithm_name: &str, secure_random: Option<Box<dyn SecureRandom>>) -> Self {
        Self {
            digest: Self::get_shake256_digest(),
            params: Arc::new(MldsaParams::by_name(algorithm_name)),
            secure_random,
            algorithm_name: algorithm_name.to_owned(),
        }
    }

    /// Return a new instance of [ShakeDigest].
    fn get_shake256_digest() -> Box<dyn Digest> {
        Box::new(ShakeDigest::new(256, None))
    }

    #[cfg(test)]
    pub fn get_ml_dsa_parameters(&self) -> &Arc<MldsaParams> {
        &self.params
    }

    fn generate_key_pair_with_secure_random(&mut self) -> (MldsaPublicKey, MldsaPrivateKey) {
        if let Some(secure_random) = &mut self.secure_random {
            let mut seed = [0u8; MldsaParams::SEED_BYTES];
            secure_random.next_bytes(&mut seed);
            let [rho, k, tr, s1, s2, t0, t1, _seed] = self.generate_key_pair_internal(&seed);
            let priv_key = MldsaPrivateKey::new(
                &self.params,
                &MldsaPrivateKey::encode(&self.params, &rho, &k, &tr, &s1, &s2, &t0),
            );
            let pub_key = MldsaPublicKey::new(&MldsaPublicKey::encode(&rho, &t1));
            (pub_key, priv_key)
        } else {
            panic!("This instance was never instantiated with a PRNG. Key generation is not available.");
        }
    }

    /*
    NIST FIPS 204 3.6.1
    Algorithm 1, implementing key generation for ML-DSA, uses an RBG to generate the 256-bit random seed
    𝜉. The seed 𝜉 shall be a fresh (i.e., not previously used) random value generated using an approved RBG,
    as prescribed in SP 800-90A, SP 800-90B, and SP 800-90C [19, 20, 21]. Moreover, the RBG used shall have
    a security strength of at least 192 bits for ML-DSA-65 and 256 bits for ML-DSA-87. For ML-DSA-44, the
    RBG should have a security strength of at least 192 bits and shall have a security strength of at least 128
    bits. If an approved RBG with at least 128 bits of security but less than 192 bits of security is used, then
    the claimed security strength of ML-DSA-44 is reduced from category 2 to category 1.
    */
    /// NIST FIPS 204 Algorithm 6: ML-DSA.KeyGen_internal(ξ), ξ: xi
    pub fn generate_key_pair_internal(&mut self, seed: &[u8]) -> [Vec<u8>; 8] {
        let mut buf = [0u8; 2 * MldsaParams::SEED_BYTES + MldsaParams::CRH_BYTES];
        let mut tr = [0u8; MldsaParams::TR_BYTES];
        let mut rho = [0u8; MldsaParams::SEED_BYTES];
        let mut rho_prime = [0u8; MldsaParams::CRH_BYTES];
        let mut key = [0u8; MldsaParams::SEED_BYTES];
        let mut a_matrix = PolyVecMatrix::new(&self.params);
        let mut t1 = PolyVecK::new(&self.params);
        let mut t0 = PolyVecK::new(&self.params);
        self.digest.update(seed);
        self.digest.update(&[u8::try_from(self.params.k).unwrap()]);
        self.digest.update(&[u8::try_from(self.params.l).unwrap()]);
        self.digest.finalize(buf.as_mut_slice());
        rho.copy_from_slice(&buf[0..MldsaParams::SEED_BYTES]);
        let mut offset = MldsaParams::SEED_BYTES;
        rho_prime.copy_from_slice(&buf[offset..offset + MldsaParams::CRH_BYTES]);
        offset += MldsaParams::CRH_BYTES;
        key.copy_from_slice(&buf[offset..offset + MldsaParams::SEED_BYTES]);
        // A is generated and stored in NTT representation as Â
        a_matrix.expand_matrix(rho.as_mut_slice());
        // (𝐬₁,𝐬₂) ← ExpandS(𝜌′)
        let mut s1 = PolyVecL::new(&self.params);
        let mut s2 = PolyVecK::new(&self.params);
        s1.uniform_eta(rho_prime.as_slice(), 0);
        s2.uniform_eta(rho_prime.as_slice(), i16::try_from(self.params.l).unwrap());
        // 𝐭 ← NTT−1 (𝐀̂ ∘ NTT(𝐬₁)) + 𝐬₂  compute 𝐭 = 𝐀𝐬₁ + 𝐬₂
        let mut s1_hat = PolyVecL::new(&self.params);
        s1.copy_poly_vec_l(&mut s1_hat);
        s1_hat.poly_vec_ntt();
        a_matrix.pointwise_montgomery(&mut t1, &mut s1_hat);
        t1.reduce();
        t1.inv_ntt_to_mont();
        t1.add_poly_vec_k(&s2);
        t1.conditional_add_q();
        // (𝐭₁,𝐭₀) ← Power2Round(𝐭)  compress 𝐭
        t1.power2round(&mut t0);
        // 𝑝𝑘 ← pkEncode(𝜌, 𝐭₁)
        let t1_enc = packing::pack_public_key_t1(&self.params, &mut t1);
        // 𝑡𝑟 ← H(𝑝𝑘, 64)
        self.digest.update(&rho);
        self.digest.update(&t1_enc);
        self.digest.finalize(&mut tr);
        // 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬₁ , 𝐬₂ , 𝐭₀)  𝐾 and 𝑡𝑟 are for use in signing
        let sk = packing::pack_secret_key(&self.params, &rho, &key, &tr, &t0, &s1, &s2);
        [
            sk[0].clone(),
            sk[1].clone(),
            sk[2].clone(),
            sk[3].clone(),
            sk[4].clone(),
            sk[5].clone(),
            t1_enc,
            seed.to_owned(),
        ]
    }

    /// Derive public key's t1 in packed format from private key packed components
    fn derive_t1(
        params: &Arc<MldsaParams>,
        rho: &[u8],
        s1_enc: &[u8],
        s2_enc: &[u8],
        t0_enc: &[u8],
    ) -> Vec<u8> {
        let mut a_matrix = PolyVecMatrix::new(params);
        let mut s1 = PolyVecL::new(params);
        let mut s2 = PolyVecK::new(params);
        let mut t1 = PolyVecK::new(params);
        let mut t0 = PolyVecK::new(params);
        packing::unpack_secret_key(params, &mut t0, &mut s1, &mut s2, t0_enc, s1_enc, s2_enc);
        // Calculate public key's polynomial vector t₁ from 𝜌 (rho) and private key's s₁, s₂ and t₀.
        a_matrix.expand_matrix(rho);
        let mut s1_hat = PolyVecL::new(params);
        s1.copy_poly_vec_l(&mut s1_hat);
        s1_hat.poly_vec_ntt();
        a_matrix.pointwise_montgomery(&mut t1, &mut s1_hat);
        t1.reduce();
        t1.inv_ntt_to_mont();
        t1.add_poly_vec_k(&s2);
        t1.conditional_add_q();
        t1.power2round(&mut t0);
        packing::pack_public_key_t1(params, &mut t1)
    }

    /*
    #[allow(dead_code)]
    pub fn init_sign(&mut self, tr: &[u8], pre_hash: bool, ctx: Option<&[u8]>) {
        self.digest.update(&tr[0..MldsaParams::TR_BYTES]);
        if let Some(ctx) = ctx {
            if pre_hash {
                self.digest.update(&[1]);
            } else {
                self.digest.update(&[0]);
            }
            self.digest.update(&[u8::try_from(ctx.len()).unwrap()]);
            self.digest.update(ctx);
        }
    }
    */

    #[allow(clippy::too_many_arguments)]
    /// NIST FIPS 204 Algorithm 7 ML-DSA.Sign_internal (start)
    fn init_and_sign_internal(
        &mut self,
        tr: &[u8],
        pre_hash: bool,
        ctx: Option<&[u8]>,
        msg: &[u8],
        rho: &[u8],
        key: &[u8],
        t0_enc: &[u8],
        s1_enc: &[u8],
        s2_enc: &[u8],
        rnd: &[u8],
    ) -> Option<Vec<u8>> {
        let mut shake256_digest = Self::get_shake256_digest();
        shake256_digest.update(&tr[0..MldsaParams::TR_BYTES]);
        if let Some(ctx) = ctx {
            if pre_hash {
                shake256_digest.update(&[1]);
            } else {
                shake256_digest.update(&[0]);
            }
            shake256_digest.update(&[u8::try_from(ctx.len()).unwrap()]);
            shake256_digest.update(ctx);
        }
        shake256_digest.update(msg);
        self.generate_signature(shake256_digest, rho, key, t0_enc, s1_enc, s2_enc, rnd)
    }

    /*
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_internal(
        &mut self,
        msg: &[u8],
        rho: &[u8],
        key: &[u8],
        t0_enc: &[u8],
        s1_enc: &[u8],
        s2_enc: &[u8],
        rnd: &[u8],
    ) -> Option<Vec<u8>> {
        let mut shake256_digest = Self::get_shake256_digest();
        shake256_digest.update(msg);
        self.generate_signature(shake256_digest, rho, key, t0_enc, s1_enc, s2_enc, rnd)
    }
    */

    #[allow(clippy::too_many_arguments)]
    /// NIST FIPS 204 Algorithm 7 ML-DSA.Sign_internal (continued)
    /// Digest should have absorbed: `BytesToBits(𝑡𝑟)||𝑀`
    fn generate_signature(
        &mut self,
        mut shake256_digest: Box<dyn Digest>,
        rho: &[u8],
        key: &[u8],
        t0_enc: &[u8],
        s1_enc: &[u8],
        s2_enc: &[u8],
        rnd: &[u8],
    ) -> Option<Vec<u8>> {
        // 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 , 64)
        let mut mu = [0u8; MldsaParams::CRH_BYTES];
        shake256_digest.finalize(&mut mu);
        // Decode secret key parts
        let mut t0 = PolyVecK::new(&self.params);
        let mut s1 = PolyVecL::new(&self.params);
        let mut s2 = PolyVecK::new(&self.params);
        let mut w1 = PolyVecK::new(&self.params);
        let mut w0 = PolyVecK::new(&self.params);
        packing::unpack_secret_key(
            &self.params,
            &mut t0,
            &mut s1,
            &mut s2,
            t0_enc,
            s1_enc,
            s2_enc,
        );
        // ŝ₁ ← NTT(s₁), ŝ₂ ← NTT(s₂),  t_hat₀ ← NTT(t₀)
        s1.poly_vec_ntt();
        s2.poly_vec_ntt();
        t0.poly_vec_ntt();
        // 𝐀 is generated and stored in NTT representation as Â
        let mut a_matrix = PolyVecMatrix::new(&self.params);
        a_matrix.expand_matrix(rho);
        // 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 , 64)
        // 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64) "compute private random seed"
        let mut key_mu =
            [0u8; MldsaParams::SEED_BYTES + MldsaParams::RND_BYTES + MldsaParams::CRH_BYTES];
        key_mu[0..MldsaParams::SEED_BYTES].copy_from_slice(&key[0..MldsaParams::SEED_BYTES]);
        let mut o = MldsaParams::SEED_BYTES;
        key_mu[o..o + MldsaParams::RND_BYTES].copy_from_slice(&rnd[0..MldsaParams::RND_BYTES]);
        o += MldsaParams::RND_BYTES;
        key_mu[o..o + MldsaParams::CRH_BYTES].copy_from_slice(&mu[0..MldsaParams::CRH_BYTES]);
        shake256_digest.update(&key_mu);
        let mut rho_double_prime = [0u8; MldsaParams::CRH_BYTES];
        shake256_digest.finalize(&mut rho_double_prime[0..MldsaParams::CRH_BYTES]);
        // initialize counter 𝜅. κ: kappa
        let mut kappa = 0;
        // (𝐳, 𝐡) ← ⊥
        let mut z = PolyVecL::new(&self.params);
        let mut h = PolyVecK::new(&self.params);
        // Initialize common rejection sampling loop variables
        let mut out_sig = vec![0u8; self.params.crypto_bytes];
        let mut y = PolyVecL::new(&self.params);
        let mut c_hat = Poly::new(&self.params);
        let w1_pack_len = self.params.k * self.params.poly_w1_packed_bytes;
        while kappa < 1000 {
            // Sample intermediate vector
            // 𝐲 ∈ 𝑅𝑞 ← ExpandMask(𝜌 , 𝜅)
            y.uniform_gamma1(&rho_double_prime, kappa);
            //kappa += i16::try_from(self.params.l).unwrap();
            kappa += 1;
            // Matrix-vector multiplication
            // w ← NTT−1 (𝐀̂ ∘ NTT(𝐲))
            // w₁ ← HighBits(𝐰) signers commitment
            y.copy_poly_vec_l(&mut z);
            z.poly_vec_ntt();
            a_matrix.pointwise_montgomery(&mut w1, &mut z);
            w1.reduce();
            w1.inv_ntt_to_mont();
            // Decompose w and call the random oracle
            w1.conditional_add_q();
            w1.decompose(&mut w0);
            out_sig[0..w1_pack_len].copy_from_slice(&w1.pack_w1());
            shake256_digest.update(&mu);
            shake256_digest.update(&out_sig[0..w1_pack_len]);
            // 𝑐 ̃ ← H(𝜇||w1Encode(𝐰1 ), 𝜆/4)
            let mut c_tilde = vec![0u8; self.params.c_tilde];
            shake256_digest.finalize(&mut c_tilde);
            // Use only the first c_tilde bytes in the signature
            out_sig[0..self.params.c_tilde].copy_from_slice(&c_tilde);
            // c ∈ 𝑅𝑞 ← SampleInBall(c_tilde)̃ verifier’s challenge
            c_hat.challenge(&c_tilde);
            // c_hat = NTT(c)
            c_hat.poly_ntt();
            // Compute z (signer's response), reject if it reveals secret
            // ⟨⟨cs₁ ⟩⟩ ← NTT−1 (c_hat ∘ ŝ₁)
            z.pointwise_poly_montgomery(&c_hat, &mut s1);
            z.inv_ntt_to_mont();
            z.add_poly_vec_l(&mut y);
            z.reduce();
            if z.check_norm(i32::try_from(self.params.gamma1 - self.params.beta).unwrap()) {
                continue;
            }
            // ⟨⟨cs₂ ⟩⟩ ← NTT−1 (c_hat ∘ ŝ₂)
            h.pointwise_poly_montgomery(&c_hat, &s2);
            h.inv_ntt_to_mont();
            w0.subtract_poly_vec_k(&h);
            w0.reduce();
            if w0.check_norm(i32::try_from(self.params.gamma2 - self.params.beta).unwrap()) {
                continue;
            }
            // ⟨⟨ct₀⟩⟩ ← NTT−1 (c_hat ∘ t₀)
            h.pointwise_poly_montgomery(&c_hat, &t0);
            h.inv_ntt_to_mont();
            h.reduce();
            if h.check_norm(i32::try_from(self.params.gamma2).unwrap()) {
                continue;
            }
            // 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0 ⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2 ⟩⟩ + ⟨⟨𝑐𝐭0 ⟩⟩) Signer’s hint
            w0.add_poly_vec_k(&h);
            w0.conditional_add_q();
            let n = h.make_hint(&w0, &w1);
            if n > i32::try_from(self.params.omega).unwrap() {
                continue;
            }
            return Some(packing::pack_signature(
                &self.params,
                &out_sig,
                &mut z,
                &mut h,
            ));
        }
        None
    }

    /*
    #[allow(dead_code)]
    pub fn verify_internal(
        &mut self,
        sig: &[u8],
        mut shake256_digest: Box<dyn Digest>,
        rho: &[u8],
        enc_t1: &[u8],
    ) -> bool {
        if sig.len() != self.params.crypto_bytes {
            return false;
        }
        let mut c2 = vec![0u8; self.params.c_tilde];
        let mut cp = Poly::new(&self.params);
        let mut a_matrix = PolyVecMatrix::new(&self.params);
        let mut z = PolyVecL::new(&self.params);
        let mut t1 = PolyVecK::new(&self.params);
        let mut w1 = PolyVecK::new(&self.params);
        let mut h = PolyVecK::new(&self.params);
        packing::unpack_public_key(&self.params, &mut t1, enc_t1);
        if !packing::unpack_signature(&self.params, &mut z, &mut h, sig) {
            return false;
        }
        // Use only first c_tilde () of c, the commitment hash.
        let c = &sig[0..self.params.c_tilde];
        if z.check_norm(i32::try_from(self.params.gamma1 - self.params.beta).unwrap()) {
            return false;
        }
        // Matrix-vector multiplication; compute Az - c2^dt1
        cp.challenge(c);
        // 𝐀 is generated and stored in NTT representation as 𝐀̂
        a_matrix.expand_matrix(rho);
        z.poly_vec_ntt();
        a_matrix.pointwise_montgomery(&mut w1, &mut z);
        cp.poly_ntt();
        t1.shift_left();
        t1.poly_vec_ntt();
        t1.pointwise_poly_montgomery_self(&cp);
        w1.subtract_poly_vec_k(&t1);
        w1.reduce();
        w1.inv_ntt_to_mont();
        // Reconstruct w1
        w1.conditional_add_q();
        w1.use_hint_self(&h);
        let buf = w1.pack_w1();
        let mut mu = [0u8; MldsaParams::CRH_BYTES];
        shake256_digest.finalize(&mut mu);
        //let mut shake256_digest = Self::get_shake256_digest();
        shake256_digest.update(&mu);
        shake256_digest.update(&buf[0..self.params.k * self.params.poly_w1_packed_bytes]);
        shake256_digest.finalize(&mut c2[0..self.params.c_tilde]);
        crate::util::maybe_constant_time_equals(c, &c2)
    }
    */

    /// NIST FIPS 204 Algorithm 8 (start)
    pub fn init_verify(&mut self, rho: &[u8], t1_enc: &[u8], pre_hash: bool, ctx: Option<&[u8]>) {
        // 𝑡𝑟 ← H(𝑝𝑘, 64)
        self.digest.update(rho);
        self.digest.update(t1_enc);
        let mut tr = [0u8; MldsaParams::TR_BYTES];
        self.digest.finalize(&mut tr);
        // self.digest ← (H(BytesToBits(𝑡𝑟)||𝑀 ′ , 64))
        self.digest.update(&tr);
        if let Some(ctx) = ctx {
            if pre_hash {
                self.digest.update(&[1]);
            } else {
                self.digest.update(&[0]);
            }
            self.digest.update(&[u8::try_from(ctx.len()).unwrap()]);
            self.digest.update(ctx);
        }
    }

    /// NIST FIPS 204 Algorithm 8 (continued)
    ///
    /// self.digest should already contain `BytesToBits(𝑡𝑟 ← H(𝑝𝑘, 64))`
    pub fn verify_internal_msg(
        &mut self,
        sig: &[u8],
        msg: &[u8],
        rho: &[u8],
        t1_encoded: &[u8],
    ) -> bool {
        if sig.len() != self.params.crypto_bytes {
            return false;
        }
        // Decode public key
        let mut t1 = PolyVecK::new(&self.params);
        packing::unpack_public_key_t1(&self.params, &mut t1, t1_encoded);
        // Decode signer’s commitment hash 𝑐,̃ response 𝐳, and hint 𝐡
        let mut z = PolyVecL::new(&self.params);
        let mut h = PolyVecK::new(&self.params);
        if !packing::unpack_signature(&self.params, &mut z, &mut h, sig) {
            return false;
        }
        // Use only first c_tilde bytes of signature.
        let c_tilde = &sig[0..self.params.c_tilde];
        if z.check_norm(i32::try_from(self.params.gamma1 - self.params.beta).unwrap()) {
            return false;
        }
        // 𝜇 ← (H(BytesToBits(𝑡𝑟)||𝑀 ′ , 64))
        let mut mu = [0u8; MldsaParams::CRH_BYTES];
        self.digest.update(msg);
        self.digest.finalize(&mut mu);
        // Matrix-vector multiplication; compute 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
        let mut c_hat = Poly::new(&self.params);
        c_hat.challenge(c_tilde);
        // 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))  𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
        c_hat.poly_ntt();
        let mut a_matrix = PolyVecMatrix::new(&self.params);
        a_matrix.expand_matrix(rho);
        z.poly_vec_ntt();
        let mut w1 = PolyVecK::new(&self.params);
        a_matrix.pointwise_montgomery(&mut w1, &mut z);
        t1.shift_left();
        t1.poly_vec_ntt();
        t1.pointwise_poly_montgomery_self(&c_hat);
        w1.subtract_poly_vec_k(&t1);
        w1.reduce();
        w1.inv_ntt_to_mont();
        w1.conditional_add_q();
        // Reconstruct signer's commitment w1
        // 𝐰1 ← UseHint(𝐡, 𝐰Approx)
        w1.use_hint_self(&h);
        // 𝑐 ′̃ ← H(𝜇||w1Encode(𝐰′1 ), 𝜆/4)
        let buf = w1.pack_w1();
        let mut shake256_digest = Self::get_shake256_digest();
        shake256_digest.update(&mu);
        shake256_digest.update(&buf[0..self.params.k * self.params.poly_w1_packed_bytes]);
        let mut c_tilde_prime = vec![0u8; self.params.c_tilde];
        shake256_digest.finalize(&mut c_tilde_prime);
        crate::util::external_constant_time_equals(c_tilde, &c_tilde_prime)
    }
}
