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

//! [PolyVecL] matrix of size K.

use super::MldsaParams;
use super::PolyVecK;
use super::PolyVecL;
use std::sync::Arc;

/// [PolyVecL] matrix of size K
#[derive(Debug)]
pub struct PolyVecMatrix {
    params: Arc<MldsaParams>,
    poly_vec_l_mat: Vec<PolyVecL>,
}

impl PolyVecMatrix {
    /// Return a new instance.
    pub fn new(params: &Arc<MldsaParams>) -> Self {
        Self {
            params: Arc::clone(params),
            poly_vec_l_mat: (0..params.k)
                .map(|_i| PolyVecL::new(params))
                .collect::<Vec<_>>(),
        }
    }

    /// NIST FIPS 204 Algorithm 32: ExpandA(ρ), [ρ: rho]
    ///
    /// Generates matrix A with uniformly random coefficients a{i,j} by
    /// performing rejection sampling on the output stream of SHAKE128(rho|j|i)
    pub fn expand_matrix(&mut self, rho: &[u8]) {
        for i in 0..self.params.k {
            for j in 0..self.params.l {
                self.poly_vec_l_mat[i]
                    .get_vector_index_mut(j)
                    .uniform_blocks(rho, i16::try_from((i << 8) + j).unwrap());
            }
        }
    }

    /// Pointwise Montgomery reduction. See also [reduce](super::poly::reduce).
    pub fn pointwise_montgomery(&mut self, t: &mut PolyVecK, v: &mut PolyVecL) {
        for i in 0..self.params.k {
            t.get_vector_index_mut(i)
                .pointwise_account_montgomery(&mut self.poly_vec_l_mat[i], v);
        }
    }
}
