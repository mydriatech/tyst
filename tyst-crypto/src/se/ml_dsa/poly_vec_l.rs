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

//! Vectors of polynomials of length L.

use super::MldsaParams;
use super::Poly;
use std::sync::Arc;

/// Vectors of polynomials of length L.
#[derive(Debug)]
pub struct PolyVecL {
    params: Arc<MldsaParams>,
    poly_vec: Vec<Poly>,
}

impl std::fmt::Display for PolyVecL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, poly) in self.poly_vec.iter().enumerate() {
            writeln!(f, "{i}: {poly}")?;
        }
        Ok(())
    }
}

impl PolyVecL {
    /// Return a new instance.
    pub fn new(params: &Arc<MldsaParams>) -> Self {
        Self {
            params: Arc::clone(params),
            poly_vec: (0..params.l)
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
        for i in 0..self.params.l {
            self.get_vector_index_mut(i)
                .uniform_eta(seed, nonce + i16::try_from(i).unwrap());
        }
    }

    /// Copy all coefficients from `self` to `out_poly`.
    pub fn copy_poly_vec_l(&mut self, out_poly: &mut PolyVecL) {
        for i in 0..self.params.l {
            for j in 0..MldsaParams::N {
                out_poly
                    .get_vector_index_mut(i)
                    .set_coeff_index(j, self.get_vector_index(i).get_coeff_index(j));
            }
        }
    }

    /// Forward NTT of all polynomials in vector of length L. Outputcoefficients
    /// can be up to 16*Q larger than input coefficients.
    pub fn poly_vec_ntt(&mut self) {
        for i in 0..self.params.l {
            self.poly_vec[i].poly_ntt();
        }
    }

    /// NIST FIPS 204 Algorithm 34 ExpandMask
    pub fn uniform_gamma1(&mut self, rho_seed: &[u8], mu: i16) {
        let l_i16 = i16::try_from(self.params.l).unwrap();
        for r in 0..l_i16 {
            self.get_vector_index_mut(usize::try_from(r).unwrap())
                .uniform_gamma1(rho_seed, l_i16 * mu + r);
        }
    }

    /// Pointwise Montgomery reduction. See also [reduce](super::poly::reduce).
    pub fn pointwise_poly_montgomery(&mut self, a: &Poly, v: &mut PolyVecL) {
        for i in 0..self.params.l {
            self.get_vector_index_mut(i)
                .pointwise_montgomery(a, v.get_vector_index(i));
        }
    }

    /// Inverse NTT and multiplication by 2^{32} of polynomials in vector of
    /// length L. Input coefficients need to be less than 2*Q.
    pub fn inv_ntt_to_mont(&mut self) {
        for i in 0..self.params.l {
            self.get_vector_index_mut(i).inv_ntt_to_mont();
        }
    }

    /// Add vectors of polynomials of length L. No modular reduction is
    /// performed.
    pub fn add_poly_vec_l(&mut self, v: &mut PolyVecL) {
        for i in 0..self.params.l {
            self.get_vector_index_mut(i).add_poly(v.get_vector_index(i));
        }
    }

    /// Reduce coefficients of polynomials in vector of length L to
    /// representatives in [-6283008,6283008].
    /// See also [reduce32()](super::poly::reduce::reduce32).
    pub fn reduce(&mut self) {
        for i in 0..self.params.l {
            self.get_vector_index_mut(i).reduce();
        }
    }

    /// Check infinity norm of polynomials in vector of length L. Assumes input
    /// [PolyVecL] to be reduced by [`reduce()`](Self::reduce).
    pub fn check_norm(&mut self, bound: i32) -> bool {
        for i in 0..self.params.l {
            if self.get_vector_index_mut(i).check_norm(bound) {
                return true;
            }
        }
        false
    }
}
