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

//! Vectors of polynomials of length K.

use super::MldsaParams;
use super::Poly;
use std::sync::Arc;

/// Vectors of polynomials of length K
#[derive(Debug)]
pub struct PolyVecK {
    params: Arc<MldsaParams>,
    poly_vec: Vec<Poly>,
}

impl std::fmt::Display for PolyVecK {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, poly) in self.poly_vec.iter().enumerate() {
            writeln!(f, "{i}: {poly}")?;
        }
        Ok(())
    }
}

impl PolyVecK {
    /// Return a new instance.
    pub fn new(params: &Arc<MldsaParams>) -> Self {
        Self {
            params: Arc::clone(params),
            poly_vec: (0..params.k)
                .map(|_i| Poly::new(params))
                .collect::<Vec<_>>(),
        }
    }

    /// Get [Poly].
    pub fn get_vector_index(&self, i: usize) -> &Poly {
        &self.poly_vec[i]
    }

    /// Get [Poly] as mutable.
    pub fn get_vector_index_mut(&mut self, i: usize) -> &mut Poly {
        &mut self.poly_vec[i]
    }

    /// See [Poly::uniform_eta].
    pub fn uniform_eta(&mut self, seed: &[u8], nonce: i16) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i)
                .uniform_eta(seed, nonce + i16::try_from(i).unwrap());
        }
    }

    /// Reduce coefficients of polynomials in vector of length K to
    /// representatives in [-6283008,6283008].
    /// See also [reduce32()](super::poly::reduce::reduce32).
    pub fn reduce(&mut self) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i).reduce();
        }
    }

    /// Inverse NTT and multiplication by 2^{32} of polynomials in vector of
    /// length K. Input coefficients need to be less than 2*Q.
    pub fn inv_ntt_to_mont(&mut self) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i).inv_ntt_to_mont();
        }
    }

    /// Add vectors of polynomials of length K. No modular reduction is
    /// performed.
    pub fn add_poly_vec_k(&mut self, b: &PolyVecK) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i).add_poly(b.get_vector_index(i));
        }
    }

    /// For all coefficients of polynomials in vector of length K add Q if
    /// coefficient is negative.
    pub fn conditional_add_q(&mut self) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i).conditional_add_q();
        }
    }

    /// For all coefficients a of polynomials in vector of length K, compute a0,
    /// a1 such that a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
    /// Assumes coefficients to be standard representatives.
    pub fn power2round(&mut self, pvk: &mut PolyVecK) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i)
                .power2round(pvk.get_vector_index_mut(i));
        }
    }

    /// Forward NTT of all polynomials in vector of length K. Output
    /// coefficients can be up to 16*Q larger than input coefficients.
    pub fn poly_vec_ntt(&mut self) {
        for i in 0..self.params.k {
            self.poly_vec[i].poly_ntt();
        }
    }

    /// For all coefficients a of polynomials in vector of length K, compute
    /// high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0 with
    /// -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we set a1 = 0 and
    /// -ALPHA/2 <= a0 = a mod Q - Q < 0. Assumes coefficients to be standard
    /// representatives.
    pub fn decompose(&mut self, v: &mut PolyVecK) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i)
                .decompose(v.get_vector_index_mut(i));
        }
    }

    /// Bitpack polynomial
    pub fn pack_w1(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.params.k * self.params.poly_w1_packed_bytes];
        for i in 0..self.params.k {
            out[i * self.params.poly_w1_packed_bytes..(i + 1) * self.params.poly_w1_packed_bytes]
                .copy_from_slice(&self.get_vector_index(i).pack_w1());
        }
        out
    }

    /// Pointwise Montgomery reduction. See also [reduce](super::poly::reduce).
    pub fn pointwise_poly_montgomery(&mut self, a: &Poly, v: &PolyVecK) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i)
                .pointwise_montgomery(a, v.get_vector_index(i));
        }
    }

    /// Pointwise Montgomery reduction. See also [reduce](super::poly::reduce).
    pub fn pointwise_poly_montgomery_self(&mut self, a: &Poly) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i).pointwise_montgomery_self(a);
        }
    }

    /// Subtract vectors of polynomials of length K. No modular reduction is
    /// performed.
    pub fn subtract_poly_vec_k(&mut self, inp_vec: &PolyVecK) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i)
                .subtract_poly(inp_vec.get_vector_index(i));
        }
    }

    /// Check infinity norm of polynomials in vector of length K. Assumes input
    /// polyveck to be reduced by polyveck_reduce().
    /// Return false if norm of all polynomials are strictly smaller than
    /// `B <= (Q-1)/8` and true otherwise.
    pub fn check_norm(&self, bound: i32) -> bool {
        for i in 0..self.params.k {
            if self.get_vector_index(i).check_norm(bound) {
                return true;
            }
        }
        false
    }

    /// Compute hint vector.
    pub fn make_hint(&mut self, v0: &PolyVecK, v1: &PolyVecK) -> i32 {
        let mut s = 0;
        for i in 0..self.params.k {
            s += self
                .get_vector_index_mut(i)
                .poly_make_hint(v0.get_vector_index(i), v1.get_vector_index(i));
        }
        s
    }

    /// Use hint vector to correct the high bits of input vector.
    pub fn use_hint_self(&mut self, h: &PolyVecK) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i)
                .poly_use_hint_self(h.get_vector_index(i));
        }
    }

    /// Multiply vector of polynomials of Length K by 2^D without modular
    /// reduction. Assumes input coefficients to be less than 2^{31-D}.
    pub fn shift_left(&mut self) {
        for i in 0..self.params.k {
            self.get_vector_index_mut(i).shift_left();
        }
    }
}
