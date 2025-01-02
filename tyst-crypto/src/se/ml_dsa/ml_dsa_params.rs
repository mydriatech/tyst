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

//! ML-DSA parameters.

use super::poly::shake_symmetric::ShakeSymmetric;

/// ML-DSA parameters as defined in NIST FIPS 204 4.
#[derive(Debug)]
pub struct MldsaParams {
    #[allow(dead_code)]
    #[doc(hidden)]
    pub claimed_security_strength: usize,
    /// k - dimensions of 𝐀, NIST FIPS 204 6.1
    pub k: usize,
    /// l - dimensions of 𝐀, NIST FIPS 204 6.1
    pub l: usize,
    #[doc(hidden)]
    /// η - private key range, NIST FIPS 204 6.1
    pub eta: usize,
    /// τ - # of ±1’s in polynomial 𝑐, NIST FIPS 204 6.2
    pub tau: usize,
    /// β = 𝜏 ⋅ 𝜂, NIST FIPS 6.2
    pub beta: usize,
    /// γ₁ - coefficient range of 𝐲, NIST FIPS 204 6.2
    pub gamma1: usize,
    /// γ₂ - low-order rounding range, NIST FIPS 204 6.2
    pub gamma2: usize,
    /// ω - max # of 1’s in the hint 𝐡, NIST FIPS 204 6.2
    pub omega: usize,
    #[doc(hidden)]
    pub poly_z_packed_bytes: usize,
    #[doc(hidden)]
    pub poly_w1_packed_bytes: usize,
    #[doc(hidden)]
    pub poly_eta_packed_bytes: usize,
    #[doc(hidden)]
    pub c_tilde: usize,
    // Derived
    #[doc(hidden)]
    pub crypto_bytes: usize,
    #[doc(hidden)]
    pub poly_uniform_gamma_1_n_blocks: usize,
    #[doc(hidden)]
    pub poly_uniform_eta_n_blocks: usize,
}

//#[allow(dead_code)]
impl MldsaParams {
    #[doc(hidden)]
    pub const N: usize = 256;
    #[doc(hidden)]
    pub const Q: usize = 8380417;
    #[doc(hidden)]
    pub const Q_INV: usize = 58728449; // q^(-1) mod 2^32
    #[doc(hidden)]
    pub const D: usize = 13;
    // 𝜁 - a 512th root of unity in ℤ𝑞, NIST FIPS 204 7.5
    //pub const ROOT_OF_UNITY: usize = 1753;

    #[doc(hidden)]
    pub const SEED_BYTES: usize = 32;
    #[doc(hidden)]
    pub const CRH_BYTES: usize = 64;
    #[doc(hidden)]
    pub const RND_BYTES: usize = 32;
    #[doc(hidden)]
    pub const TR_BYTES: usize = 64;

    #[doc(hidden)]
    pub const POLY_T0_PACKED_BYTES: usize = 416;
    #[doc(hidden)]
    pub const POLY_T1_PACKED_BYTES: usize = 320;

    /// Return a new instance for one of `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`.
    pub fn by_name(algorithm_name: &str) -> Self {
        // See Table 1 of NIST FIPS 204
        match algorithm_name {
            "ML-DSA-44" => {
                let k = 4;
                let l = 4;
                let omega = 80;
                let poly_z_packed_bytes = 576;
                let poly_eta_packed_bytes = 96;
                let c_tilde = 32;
                let poly_vec_h_packed_bytes = omega + k;
                Self {
                    claimed_security_strength: 2,
                    k,
                    l,
                    eta: 2,
                    tau: 39,
                    beta: 78,
                    gamma1: 1 << 17,
                    gamma2: (Self::Q - 1) / 88,
                    omega,
                    poly_z_packed_bytes,
                    poly_w1_packed_bytes: 192,
                    poly_eta_packed_bytes,
                    c_tilde,
                    // Derived
                    crypto_bytes: c_tilde + l * poly_z_packed_bytes + poly_vec_h_packed_bytes,
                    poly_uniform_gamma_1_n_blocks: poly_z_packed_bytes
                        .div_ceil(ShakeSymmetric::STREAM_256_BLOCK_BYTES),
                    poly_uniform_eta_n_blocks: 136 + ShakeSymmetric::STREAM_256_BLOCK_BYTES - 1,
                }
            }
            "ML-DSA-65" => {
                let k = 6;
                let l = 5;
                let omega = 55;
                let poly_z_packed_bytes = 640;
                let poly_eta_packed_bytes = 128;
                let c_tilde = 48;
                let poly_vec_h_packed_bytes = omega + k;
                Self {
                    claimed_security_strength: 3,
                    k,
                    l,
                    eta: 4,
                    tau: 49,
                    beta: 196,
                    gamma1: 1 << 19,
                    gamma2: (Self::Q - 1) / 32,
                    omega,
                    poly_z_packed_bytes,
                    poly_w1_packed_bytes: 128,
                    poly_eta_packed_bytes,
                    c_tilde,
                    // Derived
                    crypto_bytes: c_tilde + l * poly_z_packed_bytes + poly_vec_h_packed_bytes,
                    poly_uniform_gamma_1_n_blocks: poly_z_packed_bytes
                        .div_ceil(ShakeSymmetric::STREAM_256_BLOCK_BYTES),
                    poly_uniform_eta_n_blocks: 227 + ShakeSymmetric::STREAM_256_BLOCK_BYTES - 1,
                }
            }
            "ML-DSA-87" => {
                let k = 8;
                let l = 7;
                let omega = 75;
                let poly_z_packed_bytes = 640;
                let poly_eta_packed_bytes = 96;
                let c_tilde = 64;
                let poly_vec_h_packed_bytes = omega + k;
                Self {
                    claimed_security_strength: 5,
                    k,
                    l,
                    eta: 2,
                    tau: 60,
                    beta: 120,
                    gamma1: 1 << 19,
                    gamma2: (Self::Q - 1) / 32,
                    omega,
                    poly_z_packed_bytes,
                    poly_w1_packed_bytes: 128,
                    poly_eta_packed_bytes,
                    c_tilde,
                    // Derived
                    crypto_bytes: c_tilde + l * poly_z_packed_bytes + poly_vec_h_packed_bytes,
                    poly_uniform_gamma_1_n_blocks: poly_z_packed_bytes
                        .div_ceil(ShakeSymmetric::STREAM_256_BLOCK_BYTES),
                    poly_uniform_eta_n_blocks: 136 + ShakeSymmetric::STREAM_256_BLOCK_BYTES - 1,
                }
            }
            _ => panic!("Unsupported algorithm."),
        }
    }
}
