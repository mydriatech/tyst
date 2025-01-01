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

//! High-Order and Low-Order Bits and Hints.

use super::MldsaParams;

/// NIST FIPS 204 Algorithm 35
pub fn power2round(a: i32) -> [i32; 2] {
    let mut out = [0i32; 2];
    out[0] = (a + (1 << (MldsaParams::D - 1)) - 1) >> MldsaParams::D;
    out[1] = a - (out[0] << MldsaParams::D);
    out
}

/// NIST FIPS 204 Algorithm 36
pub fn decompose(a: i32, gamma2: i32) -> [i32; 2] {
    let mut a1 = (a + 127) >> 7;
    if gamma2 == ((MldsaParams::Q - 1) / 32) as i32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else if gamma2 == ((MldsaParams::Q - 1) / 88) as i32 {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    } else {
        panic!("Unsupported gamma2 '{gamma2}'.")
    }
    let mut a0 = a - a1 * 2 * gamma2;
    a0 -= (((MldsaParams::Q - 1) as i32 / 2 - a0) >> 31) & MldsaParams::Q as i32;
    [a0, a1]
}

/// NIST FIPS 204 Algorithm 39
pub fn make_hint(a0: i32, a1: i32, params: &MldsaParams) -> i32 {
    let g2 = params.gamma2 as i32;
    let q = MldsaParams::Q as i32;
    if a0 <= g2 || a0 > q - g2 || (a0 == q - g2 && a1 == 0) {
        0
    } else {
        1
    }
}

#[allow(clippy::collapsible_else_if)]
/// NIST FIPS 204 Algorithm 40
pub fn use_hint(a: i32, hint: i32, gamma2: i32) -> i32 {
    let int_array = decompose(a, gamma2);
    let a0 = int_array[0];
    let a1 = int_array[1];
    if hint == 0 {
        return a1;
    }
    if gamma2 == ((MldsaParams::Q - 1) / 32) as i32 {
        if a0 > 0 {
            (a1 + 1) & 15
        } else {
            (a1 - 1) & 15
        }
    } else if gamma2 == ((MldsaParams::Q - 1) / 88) as i32 {
        if a0 > 0 {
            if a1 == 43 {
                0
            } else {
                a1 + 1
            }
        } else {
            if a1 == 0 {
                43
            } else {
                a1 - 1
            }
        }
    } else {
        panic!("Unsupported gamma2 '{gamma2}'.")
    }
}
