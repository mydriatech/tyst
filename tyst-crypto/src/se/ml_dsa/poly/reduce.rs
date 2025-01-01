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

//! Montgomery reduction.
//!
//! See also [Wikipedia on REDC](https://en.wikipedia.org/wiki/Montgomery_modular_multiplication#The_REDC_algorithm).

use super::MldsaParams;

/// NIST FIPS 204 Algorithm 49
/// For finite field element `a` with `-2^{31}Q <= a <= Q*2^31`, compute
/// `r = a*2^{-32} (mod Q)` such that `-Q < r < Q`.
pub fn montgomery_reduce(a: i64) -> i32 {
    let q = i64::try_from(MldsaParams::Q).unwrap();
    let q_inv = i64::try_from(MldsaParams::Q_INV).unwrap();
    let a_mod_2_pow32 = a as i32;
    let t = (a_mod_2_pow32 as i64) * q_inv;
    let t_mod_2_pow32 = t as i32;
    let r = ((a - (t_mod_2_pow32 as i64) * q) as u64) >> 32;
    r as i32
}

/// For finite field element a with `a <= 2^{31} - 2^{22} - 1`, compute
/// `r = a (mod Q)` such that `-6283008 <= r <= 6283008`.
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * MldsaParams::Q as i32
}

/// Add Q if input coefficient is negative.
pub fn conditional_add_q(a: i32) -> i32 {
    a + ((a >> 31) & MldsaParams::Q as i32)
}
