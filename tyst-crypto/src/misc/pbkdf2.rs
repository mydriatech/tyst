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

//! Password-Based Key Derivation Function 2 (PBKDF2).

use tyst_traits::mac::Mac;
use tyst_traits::mac::ToMacKey;

/// Password-Based Key Derivation Function 2 (PBKDF2) defined in
/// [RFC 8018 5.2](https://www.rfc-editor.org/rfc/rfc8018#section-5.2).
pub struct Pbkdf2 {
    prf: Box<dyn Mac>,
}

impl Pbkdf2 {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-5(5) pBKDF2(12)
    pub const OID: &[u32] = &[2, 16, 840, 113549, 1, 5, 12];

    /// Return a new instance using the provided [Mac].
    pub fn new(prf: Box<dyn Mac>) -> Self {
        Self { prf }
    }

    /// Get human readable implementation identifier.
    pub fn get_algorithm_name(&self) -> String {
        "PBKDF2".to_string()
    }

    /** Derive a key using the provided input.

    [RFC 8018 4.2](https://www.rfc-editor.org/rfc/rfc8018#section-4.1):

    ```text
    In password-based encryption, the party encrypting a message can gain
    assurance that these benefits are realized simply by selecting a
    large and sufficiently random salt when deriving an encryption key
    from a password.

    The salt might have an additional, non-random octet that specifies whether
    the derived key is for encryption, for message authentication, or for some
    other operation.

    ...

    It should be at least eight octets (64 bits) long.
    ```

    [RFC 8018 4.2](https://www.rfc-editor.org/rfc/rfc8018#section-4.2):

    ```text
    Mathematically, an iteration count of c will increase the security strength
    of a password by log2(c) bits against trial-based attacks like brute force
    or dictionary attacks.

    ...

    A minimum iteration count of 1,000 is recommended.
    ```
    */
    pub fn derive_key_with_len(
        &mut self,
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        output_len_bytes: usize,
    ) -> Vec<u8> {
        let mut output = vec![0u8; output_len_bytes];
        self.derive_key(password, salt, iterations, &mut output);
        output
    }

    /// Derive a key using the provided input.
    ///
    /// See also [Self::derive_key_with_len].
    pub fn derive_key(
        &mut self,
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        output: &mut [u8],
    ) {
        let h_len = self.prf.get_mac_size_bits() >> 3;
        let dk_len = output.len();
        if dk_len > usize::try_from(u32::MAX).unwrap() * h_len {
            panic!("derived key too long");
        }
        // the number of hLen-octet blocks in the derived key
        let l = dk_len.div_ceil(h_len);
        // the number of octets in the last block
        let r = dk_len - (l - 1) * h_len;
        //log::debug!("h_len: {h_len}, dk_len: {dk_len}, l: {l}, r: {r}");
        for i in 1..l {
            self.f(
                password,
                salt,
                iterations,
                i,
                &mut output[(i - 1) * h_len..i * h_len],
            );
        }
        let mut last = vec![0u8; h_len];
        self.f(password, salt, iterations, l, &mut last);
        output[dk_len - r..dk_len].clone_from_slice(&last[0..r]);
    }

    fn f(&mut self, password: &[u8], salt: &[u8], c: usize, i: usize, output_slice: &mut [u8]) {
        let mut u = vec![0u8; output_slice.len()];
        self.prf.init(password.to_mac_key().as_ref());
        // four-octet encoding of the integer i, most significant octet first
        self.prf.update(salt);
        self.prf.update(&u32::try_from(i).unwrap().to_be_bytes());
        self.prf.finalize(&mut u);
        output_slice.clone_from_slice(&u);
        for _count in 1..c {
            self.prf.init(password.to_mac_key().as_ref());
            self.prf.update(&u);
            self.prf.finalize(&mut u);
            for i in 0..u.len() {
                output_slice[i] ^= u[i];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha3_digest::Sha3Digest;
    use crate::mac::hmac::HmacMac;
    use std::ops::Deref;
    use std::sync::LazyLock;
    use tyst_traits::CryptoRegistry;

    pub struct DummyCryptoRegistry {}
    impl CryptoRegistry for DummyCryptoRegistry {}
    static DUMMY_REGISTRY: LazyLock<DummyCryptoRegistry> = LazyLock::new(|| DummyCryptoRegistry {});

    // Test vectors from https://github.com/isaracorp/test-vectors
    const TEST_VECTORS: &[(&str, &str, &str, usize, &str)] = &[
        // PRF: HMAC-SHA3-256
        (
            "2.16.840.1.101.3.4.2.14",
            "70617373776f7264",
            "73616c74",
            1,
            "94613f3ee2ea730e0b06754f3fc816d4f87c9be9",
        ),
        (
            "2.16.840.1.101.3.4.2.14",
            "70617373776f7264",
            "73616c74",
            2,
            "4c915baedd1773383e77fcfe38114ca7514010ad",
        ),
        (
            "2.16.840.1.101.3.4.2.14",
            "70617373776f7264",
            "73616c74",
            4096,
            "778b6e237a0f49621549ff70d218d2080756b9fb",
        ),
        /* This will keep running until rangarök..
        (
            "2.16.840.1.101.3.4.2.14",
            "70617373776f7264",
            "73616c74",
            16777216,
            "e8f3e2cda7296d1df7adcf2d2bf579487431a045",
        ),
        */
        (
            "2.16.840.1.101.3.4.2.14",
            "70617373776f726450415353574f524470617373776f7264",
            "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
            4096,
            "7aef8f1ad8c7f12205334f624d4af9e2863121618f7a0b3209",
        ),
        (
            "2.16.840.1.101.3.4.2.14",
            "7061737300776f7264",
            "7361006c74",
            4096,
            "98e5503130ffdd69603da78cbb12e9becb948efa",
        ),
        // PRF: HMAC-SHA3-512
        (
            "2.16.840.1.101.3.4.2.16",
            "70617373776f7264",
            "73616c74",
            1,
            "f7a2684630ec0f81f23abbf606278deeaad1a350",
        ),
        (
            "2.16.840.1.101.3.4.2.16",
            "70617373776f7264",
            "73616c74",
            2,
            "d6824ab17801706ad465f3196eb80dde20378696",
        ),
        (
            "2.16.840.1.101.3.4.2.16",
            "70617373776f7264",
            "73616c74",
            4096,
            "2bfaf2d5ceb6d10f5e262cd902488cfd4489614e",
        ),
        /* This will keep running until rangarök..
        (
            "2.16.840.1.101.3.4.2.16",
            "70617373776f7264",
            "73616c74",
            16777216,
            "526b2f24dc0cdc77d07ffeca4e077dd80f9fb424",
        ),
        */
        (
            "2.16.840.1.101.3.4.2.16",
            "70617373776f726450415353574f524470617373776f7264",
            "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
            4096,
            "d60791a4ed27195d813f35510351b9d1ff9ad4262153944609",
        ),
        (
            "2.16.840.1.101.3.4.2.16",
            "7061737300776f7264",
            "7361006c74",
            4096,
            "c0da8018507821037c76801cccf3cc8a2b00acb7",
        ),
    ];

    #[test]
    fn test_pbkdf2() {
        for (prf_oid, password_hex, salt_hex, iterations, expected_hex) in TEST_VECTORS {
            let password = tyst_encdec::hex::decode(&password_hex).unwrap();
            let salt = tyst_encdec::hex::decode(&salt_hex).unwrap();
            let expected = tyst_encdec::hex::decode(&expected_hex).unwrap();
            let prf = get_hmac(prf_oid);
            let mut pbkdf2 = Pbkdf2::new(prf);
            let actual = pbkdf2.derive_key_with_len(&password, &salt, *iterations, expected.len());
            assert_eq!(actual, expected);
        }
    }

    fn get_hmac(oid: &str) -> Box<dyn Mac> {
        match oid {
            "2.16.840.1.101.3.4.2.14" => Box::new(HmacMac::<136>::new(
                Box::new(DUMMY_REGISTRY.deref()),
                Box::new(Sha3Digest::new(256)),
            )),
            "2.16.840.1.101.3.4.2.15" => Box::new(HmacMac::<104>::new(
                Box::new(DUMMY_REGISTRY.deref()),
                Box::new(Sha3Digest::new(384)),
            )),
            "2.16.840.1.101.3.4.2.16" => Box::new(HmacMac::<72>::new(
                Box::new(DUMMY_REGISTRY.deref()),
                Box::new(Sha3Digest::new(512)),
            )),
            _ => panic!("Unsupported!"),
        }
    }
}
