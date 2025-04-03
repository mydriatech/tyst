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

//! Common polynomial functions.

mod ntt;
pub mod reduce;
mod rounding;
pub mod shake_symmetric;

use self::shake_symmetric::ShakeSymmetric;
use super::MldsaParams;
use super::PolyVecL;
use crate::digest::shake_digest::ShakeDigest;
use std::sync::Arc;
use tyst_traits::digest::Digest;

/// Polynomial
#[derive(Debug)]
pub struct Poly {
    coeffs: [i32; MldsaParams::N],
    symmetric: ShakeSymmetric,
    params: Arc<MldsaParams>,
}

impl Poly {
    const POLY_UNIFORM_N_LEN: usize = (768 + ShakeSymmetric::STREAM_128_BLOCK_BYTES - 1);

    /// Return a new instance.
    pub fn new(params: &Arc<MldsaParams>) -> Self {
        Self {
            coeffs: [0; MldsaParams::N],
            symmetric: ShakeSymmetric::new(),
            params: Arc::clone(params),
        }
    }

    /// Return polynomial coefficient at `index`.
    pub fn get_coeff_index(&self, index: usize) -> i32 {
        self.coeffs[index]
    }

    /// Set polynomial coefficient at `index`.
    pub fn set_coeff_index(&mut self, index: usize, value: i32) {
        self.coeffs[index] = value;
    }

    /// Set all polynomial coefficients.
    pub fn set_coeffs(&mut self, coeffs: [i32; MldsaParams::N]) {
        self.coeffs = coeffs;
    }

    /// NIST FIPS 204 Algorithm 30: RejNTTPoly(𝜌), [ρ: rho] (start)
    pub fn uniform_blocks(&mut self, rho_seed: &[u8], nonce: i16) {
        let buflen = Self::POLY_UNIFORM_N_LEN;
        let mut buf = [0u8; Self::POLY_UNIFORM_N_LEN + 2];
        self.symmetric.stream_128_init(rho_seed, nonce);
        self.symmetric
            .stream_128_squeeze_blocks(&mut buf, 0, buflen);
        let mut ctr = Self::reject_uniform(self, 0, MldsaParams::N, &buf, buflen);
        // ctr can be less than N
        while ctr < MldsaParams::N {
            let off = buflen % 3;
            for i in 0..off {
                buf[i] = buf[buflen - off + i];
            }
            self.symmetric.stream_128_squeeze_blocks(
                &mut buf,
                off,
                ShakeSymmetric::STREAM_128_BLOCK_BYTES,
            );
            let buflen = ShakeSymmetric::STREAM_128_BLOCK_BYTES + off;
            ctr += Self::reject_uniform(self, ctr, MldsaParams::N - ctr, &buf, buflen);
        }
    }

    /// NIST FIPS 204 Algorithm 30: RejNTTPoly(𝜌), [ρ: rho] (continued)
    fn reject_uniform(
        &mut self,
        coeff_off: usize,
        len: usize,
        inp_buf: &[u8],
        buflen: usize,
    ) -> usize {
        let mut ctr = 0;
        let mut pos = 0;
        while ctr < len && pos + 3 <= buflen {
            let t = Self::coeff_from_three_bytes_inner(
                inp_buf[pos],
                inp_buf[pos + 1],
                inp_buf[pos + 2],
            );
            pos += 3;
            if t < i32::try_from(MldsaParams::Q).unwrap() {
                self.set_coeff_index(coeff_off + ctr, t);
                ctr += 1;
            }
        }
        ctr
    }

    /// NIST FIPS 204 Algorithm 14
    fn coeff_from_three_bytes_inner(b0: u8, b1: u8, b2: u8) -> i32 {
        let b2 = b2 & 0x7f;
        let z = ((b2 as u32) << 16) | ((b1 as u32) << 8) | b0 as u32;
        z as i32
    }

    /// Related to NIST FIPS 204 Algorithm 33  ExpandS(𝜌)
    pub fn uniform_eta(&mut self, seed: &[u8], nonce: i16) {
        let len = self.params.poly_uniform_eta_n_blocks;
        let mut buf = vec![0u8; len];
        self.symmetric.stream_256_init(seed, nonce);
        self.symmetric.stream_256_squeeze_blocks(&mut buf, 0, len);
        let mut ctr = self.reject_eta(0, MldsaParams::N, &buf, len);
        while ctr < MldsaParams::N {
            self.symmetric.stream_256_squeeze_blocks(
                &mut buf,
                0,
                ShakeSymmetric::STREAM_256_BLOCK_BYTES,
            );
            ctr += self.reject_eta(
                ctr,
                MldsaParams::N - ctr,
                &buf,
                ShakeSymmetric::STREAM_256_BLOCK_BYTES,
            );
        }
    }

    /// Related to NIST FIPS 204 Algorithm 31  RejBoundedPoly(𝜌)
    fn reject_eta(&mut self, coeff_off: usize, len: usize, buf: &[u8], buflen: usize) -> usize {
        let mut ctr = 0;
        let mut pos = 0;
        while ctr < len && pos < buflen {
            let mut t0 = buf[pos] & 0x0F;
            let mut t1 = buf[pos] >> 4;
            pos += 1;
            // NIST FIPS 204 Algorithm 15 CoeffFromHalfByte
            match self.params.eta {
                2 => {
                    if t0 < 15 {
                        t0 -= u8::try_from(((205 * usize::from(t0)) >> 10) * 5).unwrap();
                        self.set_coeff_index(coeff_off + ctr, 2 - (t0 as i32));
                        ctr += 1;
                    }
                    if t1 < 15 && ctr < len {
                        t1 -= u8::try_from(((205 * usize::from(t1)) >> 10) * 5).unwrap();
                        self.set_coeff_index(coeff_off + ctr, 2 - (t1 as i32));
                        ctr += 1;
                    }
                }
                4 => {
                    if t0 < 9 {
                        self.set_coeff_index(coeff_off + ctr, 4 - (t0 as i32));
                        ctr += 1;
                    }
                    if t1 < 9 && ctr < len {
                        self.set_coeff_index(coeff_off + ctr, 4 - (t1 as i32));
                        ctr += 1;
                    }
                }
                bad_eta => {
                    panic!("Unsupported Eta '{bad_eta}'.");
                }
            }
        }
        ctr
    }

    /// Forward NTT of this polynomial.
    pub fn poly_ntt(&mut self) {
        self.set_coeffs(ntt::ntt(&self.coeffs));
    }

    /// Pointwise Montgomery reduction between `v` and `w`. Store the result in
    /// `self`. See also [reduce].
    pub fn pointwise_montgomery(&mut self, v: &Poly, w: &Poly) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(
                i,
                reduce::montgomery_reduce(
                    i64::from(v.get_coeff_index(i)) * i64::from(w.get_coeff_index(i)),
                ),
            );
        }
    }

    /// Pointwise Montgomery reduction between `v` and `self`. Store the result
    /// in `self`. See also [reduce].
    pub fn pointwise_montgomery_self(&mut self, v: &Poly) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(
                i,
                reduce::montgomery_reduce(
                    i64::from(v.get_coeff_index(i)) * i64::from(self.get_coeff_index(i)),
                ),
            );
        }
    }

    /// Pointwise multiply vectors of polynomials of length L, multiply
    /// resulting vector by 2^{-32} and add (accumulate) polynomials in it.
    /// Input/output vectors are in NTT domain representation.
    pub fn pointwise_account_montgomery(&mut self, u: &mut PolyVecL, v: &mut PolyVecL) {
        let mut t = Poly::new(&self.params);
        self.pointwise_montgomery(u.get_vector_index(0), v.get_vector_index(0));
        for i in 1..self.params.l {
            t.pointwise_montgomery(u.get_vector_index(i), v.get_vector_index(i));
            self.add_poly(&t);
        }
    }

    /// Add coefficients of `a` to coefficients of `self`.
    pub fn add_poly(&mut self, a: &Poly) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(i, self.get_coeff_index(i) + a.get_coeff_index(i));
        }
    }

    /// Reduce. See also [reduce32()](super::poly::reduce::reduce32).
    pub fn reduce(&mut self) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(i, reduce::reduce32(self.get_coeff_index(i)));
        }
    }

    /// Inverse NTT of this polynomial.
    pub fn inv_ntt_to_mont(&mut self) {
        self.set_coeffs(ntt::inv_ntt_to_mont(&self.coeffs));
    }

    /// For all coefficients of polynomial add Q if coefficient is negative.
    pub fn conditional_add_q(&mut self) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(i, reduce::conditional_add_q(self.get_coeff_index(i)))
        }
    }

    /// See [rounding::power2round]
    pub fn power2round(&mut self, a: &mut Poly) {
        for i in 0..MldsaParams::N {
            let p2r = rounding::power2round(self.get_coeff_index(i));
            self.set_coeff_index(i, p2r[0]);
            a.set_coeff_index(i, p2r[1]);
        }
    }

    /// Bit-pack polynomial
    pub fn pack_poly_t1(&mut self) -> [u8; MldsaParams::POLY_T1_PACKED_BYTES] {
        let mut out = [0u8; MldsaParams::POLY_T1_PACKED_BYTES];
        for i in 0..MldsaParams::N / 4 {
            out[5 * i] = u8::try_from(self.coeffs[4 * i] & 0xff).unwrap();
            out[5 * i + 1] =
                u8::try_from(((self.coeffs[4 * i] >> 8) | (self.coeffs[4 * i + 1] << 2)) & 0xff)
                    .unwrap();
            out[5 * i + 2] = u8::try_from(
                ((self.coeffs[4 * i + 1] >> 6) | (self.coeffs[4 * i + 2] << 4)) & 0xff,
            )
            .unwrap();
            out[5 * i + 3] = u8::try_from(
                ((self.coeffs[4 * i + 2] >> 4) | (self.coeffs[4 * i + 3] << 6)) & 0xff,
            )
            .unwrap();
            out[5 * i + 4] = u8::try_from((self.coeffs[4 * i + 3] >> 2) & 0xff).unwrap();
        }
        out
    }

    /// Bit-unpack polynomial
    pub fn unpack_poly_t1(&mut self, a: &[u8]) {
        for i in 0..MldsaParams::N / 4 {
            self.set_coeff_index(
                4 * i,
                (i32::from(a[5 * i]) | (i32::from(a[5 * i + 1]) << 8)) & 0x3FF,
            );
            self.set_coeff_index(
                4 * i + 1,
                ((i32::from(a[5 * i + 1]) >> 2) | (i32::from(a[5 * i + 2]) << 6)) & 0x3FF,
            );
            self.set_coeff_index(
                4 * i + 2,
                ((i32::from(a[5 * i + 2]) >> 4) | (i32::from(a[5 * i + 3]) << 4)) & 0x3FF,
            );
            self.set_coeff_index(
                4 * i + 3,
                ((i32::from(a[5 * i + 3]) >> 6) | (i32::from(a[5 * i + 4]) << 2)) & 0x3FF,
            );
        }
    }

    /// Bit-pack polynomial
    #[allow(clippy::needless_range_loop)]
    pub fn poly_eta_pack<'a>(&self, out: &'a mut [u8], out_off: usize) -> &'a mut [u8] {
        let mut t = [0u8; 8];
        match self.params.eta {
            2 => {
                for i in 0..MldsaParams::N / 8 {
                    for j in 0..8 {
                        t[j] = u8::try_from(
                            (i32::try_from(self.params.eta).unwrap()
                                - self.get_coeff_index(8 * i + j))
                                & 0xff,
                        )
                        .unwrap();
                    }
                    out[out_off + 3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                    out[out_off + 3 * i + 1] =
                        (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                    out[out_off + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
                }
            }
            4 => {
                for i in 0..MldsaParams::N / 2 {
                    for j in 0..2 {
                        t[j] = u8::try_from(
                            (i32::try_from(self.params.eta).unwrap()
                                - self.get_coeff_index(2 * i + j))
                                & 0xff,
                        )
                        .unwrap();
                    }
                    out[out_off + i] = t[0] | (t[1] << 4);
                }
            }
            bad_eta => {
                panic!("Unsupported eta '{bad_eta}'.");
            }
        }
        out
    }

    pub fn unpack_poly_eta(&mut self, a: &[u8], a_off: usize) {
        let eta = i32::try_from(self.params.eta).unwrap();
        match self.params.eta {
            2 => {
                for i in 0..MldsaParams::N / 8 {
                    let base = a_off + 3 * i;
                    self.set_coeff_index(8 * i, i32::from(a[base] & 7));
                    self.set_coeff_index(8 * i + 1, i32::from((a[base] >> 3) & 7));
                    self.set_coeff_index(
                        8 * i + 2,
                        i32::from((a[base] >> 6) | (a[base + 1] << 2) & 7),
                    );
                    self.set_coeff_index(8 * i + 3, i32::from((a[base + 1] >> 1) & 7));
                    self.set_coeff_index(8 * i + 4, i32::from((a[base + 1] >> 4) & 7));
                    self.set_coeff_index(
                        8 * i + 5,
                        i32::from((a[base + 1] >> 7) | (a[base + 2] << 1) & 7),
                    );
                    self.set_coeff_index(8 * i + 6, i32::from((a[base + 2] >> 2) & 7));
                    self.set_coeff_index(8 * i + 7, i32::from((a[base + 2] >> 5) & 7));
                    for j in 0..8 {
                        self.set_coeff_index(8 * i + j, eta - self.get_coeff_index(8 * i + j));
                    }
                }
            }
            4 => {
                for i in 0..MldsaParams::N / 2 {
                    self.set_coeff_index(2 * i, i32::from(a[a_off + i] & 0x0f));
                    self.set_coeff_index(2 * i + 1, i32::from((a[a_off + i] & 0xf0) >> 4));
                    for j in 0..2 {
                        self.set_coeff_index(2 * i + j, eta - self.get_coeff_index(2 * i + j));
                    }
                }
            }
            bad_eta => {
                panic!("Unsupported eta '{bad_eta}'.");
            }
        }
    }

    /// Bit-pack polynomial
    pub fn pack_poly_t0<'a>(&self, out: &'a mut [u8], out_off: usize) -> &'a mut [u8] {
        let mut t = [0i32; 8];
        #[allow(clippy::needless_range_loop)]
        for i in 0..MldsaParams::N / 8 {
            for j in 0..8 {
                t[j] = (1 << (MldsaParams::D - 1)) - self.get_coeff_index(8 * i + j);
            }
            let base = out_off + 13 * i;
            out[base] = u8::try_from(t[0] & 0xff).unwrap();
            out[base + 1] = u8::try_from((t[0] >> 8) & 0xff).unwrap();
            out[base + 1] |= u8::try_from((t[1] << 5) & 0xff).unwrap();
            out[base + 2] = u8::try_from((t[1] >> 3) & 0xff).unwrap();
            out[base + 3] = u8::try_from((t[1] >> 11) & 0xff).unwrap();
            out[base + 3] |= u8::try_from((t[2] << 2) & 0xff).unwrap();
            out[base + 4] = u8::try_from((t[2] >> 6) & 0xff).unwrap();
            out[base + 4] |= u8::try_from((t[3] << 7) & 0xff).unwrap();
            out[base + 5] = u8::try_from((t[3] >> 1) & 0xff).unwrap();
            out[base + 6] = u8::try_from((t[3] >> 9) & 0xff).unwrap();
            out[base + 6] |= u8::try_from((t[4] << 4) & 0xff).unwrap();
            out[base + 7] = u8::try_from((t[4] >> 4) & 0xff).unwrap();
            out[base + 8] = u8::try_from((t[4] >> 12) & 0xff).unwrap();
            out[base + 8] |= u8::try_from((t[5] << 1) & 0xff).unwrap();
            out[base + 9] = u8::try_from((t[5] >> 7) & 0xff).unwrap();
            out[base + 9] |= u8::try_from((t[6] << 6) & 0xff).unwrap();
            out[base + 10] = u8::try_from((t[6] >> 2) & 0xff).unwrap();
            out[base + 11] = u8::try_from((t[6] >> 10) & 0xff).unwrap();
            out[base + 11] |= u8::try_from((t[7] << 3) & 0xff).unwrap();
            out[base + 12] = u8::try_from((t[7] >> 5) & 0xff).unwrap();
        }
        out
    }

    /// Bit-unpack polynomial
    pub fn unpack_poly_t0(&mut self, a: &[u8], a_off: usize) {
        for i in 0..MldsaParams::N / 8 {
            let base = a_off + 13 * i;
            self.set_coeff_index(
                8 * i,
                (i32::from(a[base]) | (i32::from(a[base + 1]) << 8)) & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 1,
                ((i32::from(a[base + 1]) >> 5)
                    | (i32::from(a[base + 2]) << 3)
                    | (i32::from(a[base + 3]) << 11))
                    & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 2,
                ((i32::from(a[base + 3]) >> 2) | (i32::from(a[base + 4]) << 6)) & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 3,
                ((i32::from(a[base + 4]) >> 7)
                    | (i32::from(a[base + 5]) << 1)
                    | (i32::from(a[base + 6]) << 9))
                    & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 4,
                ((i32::from(a[base + 6]) >> 4)
                    | (i32::from(a[base + 7]) << 4)
                    | (i32::from(a[base + 8]) << 12))
                    & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 5,
                ((i32::from(a[base + 8]) >> 1) | (i32::from(a[base + 9]) << 7)) & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 6,
                ((i32::from(a[base + 9]) >> 6)
                    | (i32::from(a[base + 10]) << 2)
                    | (i32::from(a[base + 11]) << 10))
                    & 0x1FFF,
            );
            self.set_coeff_index(
                8 * i + 7,
                ((i32::from(a[base + 11]) >> 3) | (i32::from(a[base + 12]) << 5)) & 0x1FFF,
            );
            for j in 0..8 {
                self.set_coeff_index(
                    8 * i + j,
                    (1 << (MldsaParams::D - 1)) - self.get_coeff_index(8 * i + j),
                );
            }
        }
    }

    /// NIST FIPS 204 Algorithm 34 ExpandMask
    pub fn uniform_gamma1(&mut self, rho_seed: &[u8], mu_r_c_nonce: i16) {
        let mut buf = vec![
            0u8;
            self.params.poly_uniform_gamma_1_n_blocks
                * ShakeSymmetric::STREAM_256_BLOCK_BYTES
        ];
        self.symmetric.stream_256_init(rho_seed, mu_r_c_nonce);
        let len = buf.len();
        self.symmetric
            .stream_256_squeeze_blocks(buf.as_mut_slice(), 0, len);
        self.unpack_z(&buf);
    }

    /// Bit-unpack signer's response
    pub fn unpack_z(&mut self, a: &[u8]) {
        // Until https://github.com/rust-lang/rust/issues/76001
        const GAMMA1_L17: usize = 1 << 17;
        const GAMMA1_L19: usize = 1 << 19;
        match self.params.gamma1 {
            GAMMA1_L17 => {
                for i in 0..MldsaParams::N / 4 {
                    self.set_coeff_index(
                        4 * i,
                        ((i32::from(a[9 * i]))
                            | (i32::from(a[9 * i + 1]) << 8)
                            | (i32::from(a[9 * i + 2]) << 16))
                            & 0x3FFFF,
                    );
                    self.set_coeff_index(
                        4 * i + 1,
                        ((i32::from(a[9 * i + 2]) >> 2)
                            | (i32::from(a[9 * i + 3]) << 6)
                            | (i32::from(a[9 * i + 4]) << 14))
                            & 0x3FFFF,
                    );
                    self.set_coeff_index(
                        4 * i + 2,
                        ((i32::from(a[9 * i + 4]) >> 4)
                            | (i32::from(a[9 * i + 5]) << 4)
                            | (i32::from(a[9 * i + 6]) << 12))
                            & 0x3FFFF,
                    );
                    self.set_coeff_index(
                        4 * i + 3,
                        ((i32::from(a[9 * i + 6]) >> 6)
                            | (i32::from(a[9 * i + 7]) << 2)
                            | (i32::from(a[9 * i + 8]) << 10))
                            & 0x3FFFF,
                    );
                    for j in 0..4 {
                        self.set_coeff_index(
                            4 * i + j,
                            i32::try_from(self.params.gamma1).unwrap()
                                - self.get_coeff_index(4 * i + j),
                        );
                    }
                }
            }
            GAMMA1_L19 => {
                for i in 0..MldsaParams::N / 2 {
                    self.set_coeff_index(
                        2 * i,
                        (i32::from(a[5 * i])
                            | (i32::from(a[5 * i + 1]) << 8)
                            | (i32::from(a[5 * i + 2]) << 16))
                            & 0xFFFFF,
                    );
                    self.set_coeff_index(
                        2 * i + 1,
                        ((i32::from(a[5 * i + 2]) >> 4)
                            | (i32::from(a[5 * i + 3]) << 4)
                            | (i32::from(a[5 * i + 4]) << 12))
                            & 0xFFFFF,
                    );
                    for j in 0..2 {
                        self.set_coeff_index(
                            2 * i + j,
                            i32::try_from(self.params.gamma1).unwrap()
                                - self.get_coeff_index(2 * i + j),
                        );
                    }
                }
            }
            bad_gamma1 => {
                panic!("Bad bad_gamma1 '{bad_gamma1:x}'");
            }
        }
    }

    /// See [rounding::decompose].
    pub fn decompose(&mut self, a: &mut Poly) {
        for i in 0..MldsaParams::N {
            let decomp = rounding::decompose(
                self.get_coeff_index(i),
                i32::try_from(self.params.gamma2).unwrap(),
            );
            self.set_coeff_index(i, decomp[1]);
            a.set_coeff_index(i, decomp[0]);
        }
    }

    #[allow(clippy::needless_range_loop)]
    /// Bit-pack signers commitment w₁.
    ///
    /// There is no corresponding unpack. w₁ is recreated during signature verification.
    pub fn pack_w1(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.params.poly_w1_packed_bytes];
        if self.params.gamma2 == (MldsaParams::Q - 1) / 88 {
            for i in 0..MldsaParams::N / 4 {
                out[3 * i] = u8::try_from(self.get_coeff_index(4 * i) & 0xff).unwrap()
                    | u8::try_from((self.get_coeff_index(4 * i + 1) << 6) & 0xff).unwrap();
                out[3 * i + 1] = u8::try_from((self.get_coeff_index(4 * i + 1) >> 2) & 0xff)
                    .unwrap()
                    | u8::try_from((self.get_coeff_index(4 * i + 2) << 4) & 0xff).unwrap();
                out[3 * i + 2] = u8::try_from((self.get_coeff_index(4 * i + 2) >> 4) & 0xff)
                    .unwrap()
                    | u8::try_from((self.get_coeff_index(4 * i + 3) << 2) & 0xff).unwrap();
            }
        } else if self.params.gamma2 == (MldsaParams::Q - 1) / 32 {
            for i in 0..MldsaParams::N / 2 {
                out[i] = u8::try_from(self.get_coeff_index(2 * i) & 0xff).unwrap()
                    | u8::try_from((self.get_coeff_index(2 * i + 1) << 4) & 0xff).unwrap();
            }
        }
        out
    }

    #[allow(clippy::needless_range_loop)]
    /// NIST FIPS 204 Algorithm 29 SampleInBall(c_tilde), c=self
    pub fn challenge(&mut self, c_tilde_seed: &[u8]) {
        let mut buf = [0u8; ShakeSymmetric::STREAM_256_BLOCK_BYTES];
        let mut shake256_digest: Box<dyn Digest> = Box::new(ShakeDigest::new(256, None));
        shake256_digest.update(&c_tilde_seed[0..self.params.c_tilde]);
        shake256_digest.finalize(buf.as_mut_slice());
        let mut signs = 0u64;
        for i in 0..8 {
            signs |= u64::from(buf[i]) << (8 * i);
        }
        for i in 0..MldsaParams::N {
            self.set_coeff_index(i, 0);
        }
        let mut pos = 8;
        for i in (MldsaParams::N - self.params.tau)..MldsaParams::N {
            let mut j;
            loop {
                if pos >= ShakeSymmetric::STREAM_256_BLOCK_BYTES {
                    shake256_digest.finalize(buf.as_mut_slice());
                    pos = 0;
                }
                j = usize::from(buf[pos]);
                pos += 1;
                if j <= i {
                    break;
                }
            }
            self.set_coeff_index(i, self.get_coeff_index(j));
            self.set_coeff_index(j, 1 - 2 * (i32::try_from(signs & 1).unwrap()));
            signs >>= 1;
        }
    }

    /// Check infinity norm of polynomial
    /// Return false if norm of all polynomial is strictly smaller than
    /// `B <= (Q-1)/8` and true otherwise.
    pub fn check_norm(&self, bound: i32) -> bool {
        if bound > i32::try_from((MldsaParams::Q - 1) / 8).unwrap() {
            return true;
        }
        for i in 0..MldsaParams::N {
            let mut t = self.get_coeff_index(i) >> 31;
            t = self.get_coeff_index(i) - (t & (2 * self.get_coeff_index(i)));
            if t >= bound {
                return true;
            }
        }
        false
    }

    /// Subtract coefficients of `a` to coefficients of `self`.
    pub fn subtract_poly(&mut self, inp_poly: &Poly) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(i, self.get_coeff_index(i) - inp_poly.get_coeff_index(i));
        }
    }

    /// Compute hint. See also [rounding::make_hint].
    pub fn poly_make_hint(&mut self, a0: &Poly, a1: &Poly) -> i32 {
        let mut s = 0;
        for i in 0..MldsaParams::N {
            self.set_coeff_index(
                i,
                rounding::make_hint(a0.get_coeff_index(i), a1.get_coeff_index(i), &self.params),
            );
            s += self.get_coeff_index(i);
        }
        s
    }

    /// Use hint vector `h` to correct the high bits of input vector.
    /// See also [rounding::use_hint].
    pub fn poly_use_hint_self(&mut self, h: &Poly) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(
                i,
                rounding::use_hint(
                    self.get_coeff_index(i),
                    h.get_coeff_index(i),
                    i32::try_from(self.params.gamma2).unwrap(),
                ),
            );
        }
    }

    #[allow(clippy::needless_range_loop)]
    /// Bit-pack signer's response
    pub fn pack_z(&self) -> Vec<u8> {
        let mut out_bytes = vec![0u8; self.params.poly_z_packed_bytes];
        let mut t = [0i32; 4];
        const GAMMA1_L17: usize = 1 << 17;
        const GAMMA1_L19: usize = 1 << 19;
        match self.params.gamma1 {
            GAMMA1_L17 => {
                for i in 0..MldsaParams::N / 4 {
                    for j in 0..4 {
                        t[j] = i32::try_from(self.params.gamma1).unwrap()
                            - self.get_coeff_index(4 * i + j);
                    }
                    out_bytes[9 * i] = u8::try_from(t[0] & 0xff).unwrap();
                    out_bytes[9 * i + 1] = u8::try_from((t[0] >> 8) & 0xff).unwrap();
                    out_bytes[9 * i + 2] = u8::try_from((t[0] >> 16) & 0xff).unwrap()
                        | u8::try_from((t[1] << 2) & 0xff).unwrap();
                    out_bytes[9 * i + 3] = u8::try_from((t[1] >> 6) & 0xff).unwrap();
                    out_bytes[9 * i + 4] = u8::try_from((t[1] >> 14) & 0xff).unwrap()
                        | u8::try_from((t[2] << 4) & 0xff).unwrap();
                    out_bytes[9 * i + 5] = u8::try_from((t[2] >> 4) & 0xff).unwrap();
                    out_bytes[9 * i + 6] = u8::try_from((t[2] >> 12) & 0xff).unwrap()
                        | u8::try_from((t[3] << 6) & 0xff).unwrap();
                    out_bytes[9 * i + 7] = u8::try_from((t[3] >> 2) & 0xff).unwrap();
                    out_bytes[9 * i + 8] = u8::try_from((t[3] >> 10) & 0xff).unwrap();
                }
            }
            GAMMA1_L19 => {
                for i in 0..MldsaParams::N / 2 {
                    for j in 0..2 {
                        t[j] = i32::try_from(self.params.gamma1).unwrap()
                            - self.get_coeff_index(2 * i + j);
                    }
                    out_bytes[5 * i] = u8::try_from(t[0] & 0xff).unwrap();
                    out_bytes[5 * i + 1] = u8::try_from((t[0] >> 8) & 0xff).unwrap();
                    out_bytes[5 * i + 2] = u8::try_from((t[0] >> 16) & 0xff).unwrap()
                        | u8::try_from((t[1] << 4) & 0xff).unwrap();
                    out_bytes[5 * i + 3] = u8::try_from((t[1] >> 4) & 0xff).unwrap();
                    out_bytes[5 * i + 4] = u8::try_from((t[1] >> 12) & 0xff).unwrap();
                }
            }
            bad_gamma1 => {
                panic!("Bad bad_gamma1 '{bad_gamma1:x}'");
            }
        }
        out_bytes
    }

    /// Bit-shift each coefficient of `self` [MldsaParams::D] steps left.
    pub fn shift_left(&mut self) {
        for i in 0..MldsaParams::N {
            self.set_coeff_index(i, self.get_coeff_index(i) << MldsaParams::D);
        }
    }
}
