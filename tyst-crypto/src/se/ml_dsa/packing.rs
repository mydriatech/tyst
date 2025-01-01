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

//! Bit-pack/unpack functions.

use super::MldsaParams;
use super::PolyVecK;
use super::PolyVecL;

/// Bit-pack t1 of the public key pk = (rho, t1).
pub fn pack_public_key_t1(params: &MldsaParams, t1: &mut PolyVecK) -> Vec<u8> {
    let mut out = vec![0u8; params.k * MldsaParams::POLY_T1_PACKED_BYTES];
    for i in 0..params.k {
        out[i * MldsaParams::POLY_T1_PACKED_BYTES..(i + 1) * MldsaParams::POLY_T1_PACKED_BYTES]
            .copy_from_slice(&t1.get_vector_index_mut(i).pack_poly_t1());
    }
    out
}

/// Unpack t1 of the public key pk = (rho, t1).
pub fn unpack_public_key_t1(params: &MldsaParams, t1: &mut PolyVecK, public_key: &[u8]) {
    for i in 0..params.k {
        let mut packed_poly_t1 = [0u8; MldsaParams::POLY_T1_PACKED_BYTES];
        packed_poly_t1.copy_from_slice(
            &public_key[i * MldsaParams::POLY_T1_PACKED_BYTES
                ..(i + 1) * MldsaParams::POLY_T1_PACKED_BYTES],
        );
        t1.get_vector_index_mut(i).unpack_poly_t1(&packed_poly_t1);
    }
}

/// Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
/// Returns [rho, k, tr, s1_encoded, s2_encoded, t0].
pub fn pack_secret_key(
    params: &MldsaParams,
    rho: &[u8],
    key: &[u8],
    tr: &[u8],
    t0: &PolyVecK,
    s1: &PolyVecL,
    s2: &PolyVecK,
) -> Vec<Vec<u8>> {
    let mut out = vec![Vec::<u8>::new(); 6];
    out[0] = rho.to_vec();
    out[1] = key.to_vec();
    out[2] = tr.to_vec();
    out[3] = vec![0u8; params.l * params.poly_eta_packed_bytes];
    for i in 0..params.l {
        s1.get_vector_index(i)
            .poly_eta_pack(&mut out[3], i * params.poly_eta_packed_bytes);
    }
    out[4] = vec![0u8; params.k * params.poly_eta_packed_bytes];
    for i in 0..params.k {
        s2.get_vector_index(i)
            .poly_eta_pack(&mut out[4], i * params.poly_eta_packed_bytes);
    }
    out[5] = vec![0u8; params.k * MldsaParams::POLY_T0_PACKED_BYTES];
    for i in 0..params.k {
        t0.get_vector_index(i)
            .pack_poly_t0(&mut out[5], i * MldsaParams::POLY_T0_PACKED_BYTES);
    }
    out
}

/// Unpack secret key sk = (rho, tr, key, t0, s1, s2).
pub fn unpack_secret_key(
    params: &MldsaParams,
    t0: &mut PolyVecK,
    s1: &mut PolyVecL,
    s2: &mut PolyVecK,
    t0_enc: &[u8],
    s1_enc: &[u8],
    s2_enc: &[u8],
) {
    for i in 0..params.l {
        s1.get_vector_index_mut(i)
            .unpack_poly_eta(s1_enc, i * params.poly_eta_packed_bytes);
    }
    for i in 0..params.k {
        s2.get_vector_index_mut(i)
            .unpack_poly_eta(s2_enc, i * params.poly_eta_packed_bytes);
    }
    for i in 0..params.k {
        t0.get_vector_index_mut(i)
            .unpack_poly_t0(t0_enc, i * MldsaParams::POLY_T0_PACKED_BYTES);
    }
}

/// Bit-pack signature sig = (challenge_hash, z, hint_vector).
pub fn pack_signature(
    params: &MldsaParams,
    c: &[u8],
    z: &mut PolyVecL,
    h: &mut PolyVecK,
) -> Vec<u8> {
    let mut out_bytes = vec![0u8; params.crypto_bytes];
    out_bytes[0..params.c_tilde].copy_from_slice(&c[0..params.c_tilde]);
    let mut offset = params.c_tilde;
    for i in 0..params.l {
        out_bytes
            [offset + i * params.poly_z_packed_bytes..offset + (i + 1) * params.poly_z_packed_bytes]
            .copy_from_slice(&z.get_vector_index_mut(i).pack_z())
    }
    offset += params.l * params.poly_z_packed_bytes;
    let mut k = 0;
    for i in 0..params.k {
        for j in 0..MldsaParams::N {
            if h.get_vector_index(i).get_coeff_index(j) != 0 {
                out_bytes[offset + k] = u8::try_from(j).unwrap();
                k += 1;
            }
        }
        out_bytes[offset + params.omega + i] = u8::try_from(k).unwrap();
    }
    out_bytes
}

/// Unpack signature sig = (challenge_hash, z, hint_vector).
pub fn unpack_signature(
    params: &MldsaParams,
    z: &mut PolyVecL,
    h: &mut PolyVecK,
    sig: &[u8],
) -> bool {
    let mut offset = params.c_tilde;
    for i in 0..params.l {
        let mut packed_poly_z = vec![0u8; params.poly_z_packed_bytes];
        packed_poly_z.copy_from_slice(
            &sig[offset + i * params.poly_z_packed_bytes
                ..offset + (i + 1) * params.poly_z_packed_bytes],
        );
        z.get_vector_index_mut(i).unpack_z(&packed_poly_z);
    }
    offset += params.l * params.poly_z_packed_bytes;
    let mut k = 0;
    for i in 0..params.k {
        for j in 0..MldsaParams::N {
            h.get_vector_index_mut(i).set_coeff_index(j, 0);
        }
        if sig[offset + params.omega + i] < k
            || sig[offset + params.omega + i] > u8::try_from(params.omega).unwrap()
        {
            return false;
        }
        for j in k..sig[offset + params.omega + i] {
            if j > k && sig[offset + usize::from(j)] <= sig[offset + usize::from(j) - 1] {
                return false;
            }
            h.get_vector_index_mut(i)
                .set_coeff_index(usize::from(sig[offset + usize::from(j)]), 1);
        }
        k = sig[offset + params.omega + i];
    }
    for j in usize::from(k)..params.omega {
        if sig[offset + j] != 0 {
            return false;
        }
    }
    true
}
