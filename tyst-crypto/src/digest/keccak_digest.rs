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

//! The Keccak message digest algorithm.

use tyst_traits::digest::Digest;
use tyst_traits::digest::DigestParams;
use tyst_traits::factory::AlgorithmMetaData;
use tyst_traits::factory::Factory;
use tyst_traits::CryptoRegistry;

/// Factory for [KeccakDigest].
pub struct KeccakDigestFactory {
    provided: Vec<AlgorithmMetaData>,
}

impl Default for KeccakDigestFactory {
    fn default() -> Self {
        Self {
            provided: vec![
                AlgorithmMetaData::new("Keccak-128", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("Keccak-224", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("Keccak-256", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("Keccak-288", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("Keccak-384", env!("CARGO_PKG_NAME")),
                AlgorithmMetaData::new("Keccak-512", env!("CARGO_PKG_NAME")),
            ],
        }
    }
}

impl Factory for KeccakDigestFactory {
    type Type = dyn Digest;
    type Parameters = DigestParams;

    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData] {
        &self.provided
    }

    fn new_by_name(
        &self,
        _registry: Box<&'static dyn CryptoRegistry>,
        algorithm_name: &str,
        _params: Self::Parameters,
    ) -> Box<Self::Type> {
        match algorithm_name {
            "Keccak-128" => Box::new(KeccakDigest::new(128)),
            "Keccak-224" => Box::new(KeccakDigest::new(224)),
            "Keccak-256" => Box::new(KeccakDigest::new(256)),
            "Keccak-288" => Box::new(KeccakDigest::new(288)),
            "Keccak-384" => Box::new(KeccakDigest::new(384)),
            "Keccak-512" => Box::new(KeccakDigest::new(512)),
            _ => panic!("not implemented"),
        }
    }
}

/// Keccak message digest implementation
pub struct KeccakDigest {
    state: [u64; 25],
    data_queue: [u8; 192],
    rate: usize,
    bits_in_queue: usize,
    fixed_output_length: usize,
    squeezing: bool,
}

impl KeccakDigest {
    #[doc(hidden)]
    const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    #[doc(hidden)]
    const ALGORITHM_NAME_PREFIX: &str = "Keccak-";

    #[doc(hidden)]
    const ALLOWED_BIT_LENGTHS: [usize; 6] = [128, 224, 256, 288, 384, 512];

    #[doc(hidden)]
    /// Return a new instance
    pub fn new(bit_length: usize) -> Self {
        if !Self::ALLOWED_BIT_LENGTHS.contains(&bit_length) {
            panic!("Bit length must be one of {:?}.", Self::ALLOWED_BIT_LENGTHS);
        }
        let rate = 1600 - (bit_length << 1);
        if rate == 0 || rate >= 1600 || (rate % 64) != 0 {
            panic!("Invalid rate value");
        }
        Self {
            state: [0; 25],
            data_queue: [0; 192],
            rate,
            bits_in_queue: 0,
            fixed_output_length: (1600 - rate) / 2,
            squeezing: false,
        }
    }

    /// Return true if squeezing phase has been started. (Absorb is no longer possible.)
    pub fn get_squeezing(&self) -> bool {
        self.squeezing
    }

    /// Absorb as much as possible from the slice and leave the rest in the data queue
    fn absorb_slice(&mut self, data: &[u8], off: usize, len: usize) {
        if (self.bits_in_queue % 8) != 0 {
            panic!("attempt to absorb with odd length queue");
        }
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }

        let bytes_in_queue = self.bits_in_queue >> 3;
        let rate_bytes = self.rate >> 3;

        let available = rate_bytes - bytes_in_queue;
        if len < available {
            self.data_queue[bytes_in_queue..bytes_in_queue + len]
                .copy_from_slice(&data[off..off + len]);
            self.bits_in_queue += len << 3;
            return;
        }
        let mut count = 0;
        if bytes_in_queue > 0 {
            self.data_queue[bytes_in_queue..bytes_in_queue + available]
                .copy_from_slice(&data[off..off + available]);
            count += available;
            self.keccak_absorb_data_queue();
        }
        let mut remaining;
        loop {
            remaining = len - count;
            if remaining < rate_bytes {
                break;
            }
            self.keccak_absorb(data, off + count);
            count += rate_bytes;
        }
        self.data_queue[0..remaining].copy_from_slice(&data[off + count..off + count + remaining]);
        self.bits_in_queue = remaining << 3;
    }

    /// Absorb (final) bits into data queue.
    ///
    /// No more data can be absorbed after this point, since the queue is no longer an %8=0 number of bits.
    pub fn absorb_bits(&mut self, data: u8, bits: usize) {
        if !(1..=7).contains(&bits) {
            panic!("'bits' must be in the range 1 to 7");
        }
        if (self.bits_in_queue % 8) != 0 {
            panic!("attempt to absorb with odd length queue");
        }
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }
        let mask = (1 << bits) - 1;
        self.data_queue[self.bits_in_queue >> 3] = data & mask;
        self.bits_in_queue += bits;
    }

    /// Absorb `rate/64` full 64-bit little endian encoded words from data queue
    fn keccak_absorb_data_queue(&mut self) {
        let count = self.rate >> 6;
        let mut offset = 0;
        for state in &mut self.state[0..count] {
            *state ^= Self::u64_from_le_slice(&self.data_queue, offset);
            offset += size_of::<u64>();
        }
        self.keccak_permutation();
    }

    /// Absorb `rate/64` full 64-bit little endian encoded words from data
    fn keccak_absorb(&mut self, data: &[u8], mut offset: usize) {
        let count = self.rate >> 6;
        for state in &mut self.state[0..count] {
            *state ^= Self::u64_from_le_slice(data, offset);
            offset += size_of::<u64>();
        }
        self.keccak_permutation();
    }

    /// Start squeezing phase and write internal output state to `output`.
    fn squeeze(&mut self, output: &mut [u8]) {
        if !self.squeezing {
            self.pad_and_switch_to_squeezing_phase();
        }
        let output_len_bits = output.len() << 3;
        let mut i = 0;
        while i < output_len_bits {
            if self.bits_in_queue == 0 {
                self.keccak_extract();
            }
            let partial_block = std::cmp::min(self.bits_in_queue, output_len_bits - i);
            output[(i >> 3)..(i >> 3) + (partial_block >> 3)].copy_from_slice(
                &self.data_queue[((self.rate - self.bits_in_queue) >> 3)
                    ..((self.rate - self.bits_in_queue) >> 3) + (partial_block >> 3)],
            );
            self.bits_in_queue -= partial_block;
            i += partial_block;
        }
    }

    /// Add padding and absorb any data left in the data queue
    fn pad_and_switch_to_squeezing_phase(&mut self) {
        self.data_queue[self.bits_in_queue >> 3] |=
            u8::try_from(1 << (self.bits_in_queue & 7)).unwrap();
        self.bits_in_queue += 1;

        if self.bits_in_queue == self.rate {
            self.keccak_absorb_data_queue();
        } else {
            let full = self.bits_in_queue >> 6;
            let partial = self.bits_in_queue & 63;
            let mut off = 0;
            for i in 0..full {
                self.state[i] ^= Self::u64_from_le_slice(&self.data_queue, off);
                off += 8;
            }
            if partial > 0 {
                let mask: u64 = (1 << partial) - 1;
                self.state[full] ^= Self::u64_from_le_slice(&self.data_queue, off) & mask;
            }
        }
        self.state[(self.rate - 1) >> 6] ^= 1u64 << 63;
        self.bits_in_queue = 0;
        self.squeezing = true;
    }

    /// Add permuted state to data queue
    fn keccak_extract(&mut self) {
        self.keccak_permutation();
        let mut dq_start = 0;
        let mut dq_end = 0;
        for n in self.state.iter().take(self.rate >> 6) {
            dq_end += size_of::<u64>();
            self.data_queue[dq_start..dq_end].copy_from_slice(&n.to_le_bytes());
            dq_start += size_of::<u64>();
        }
        self.bits_in_queue = self.rate;
    }

    /// The Keccak permutation.
    ///
    /// In the words of holistic detective Dirk Gently: "Everything is connected. Nothing is also connected."
    fn keccak_permutation(&mut self) {
        let a = &mut self.state;
        for round in 0..24 {
            // Theta
            let c = &mut [0u64; 5];
            for i in 0..=4 {
                c[i] = a[i] ^ a[5 + i] ^ a[10 + i] ^ a[15 + i] ^ a[20 + i];
            }
            let d = &mut [0u64; 5];
            for i in 0..=4 {
                d[(i + 1) % 5] = c[(i + 1) % 5].rotate_left(1) ^ c[(i + 4) % 5];
            }
            for i in 0..=4 {
                for j in (0..=20).step_by(5) {
                    a[j + i] ^= d[(i + 1) % 5];
                }
            }
            // Rho/Pi
            c[1] = a[1].rotate_left(1);
            a[1] = a[6].rotate_right(20);
            a[6] = a[9].rotate_left(20);
            a[9] = a[22].rotate_right(3);
            a[22] = a[14].rotate_right(25);
            a[14] = a[20].rotate_left(18);
            a[20] = a[2].rotate_right(2);
            a[2] = a[12].rotate_right(21);
            a[12] = a[13].rotate_left(25);
            a[13] = a[19].rotate_left(8);
            a[19] = a[23].rotate_right(8);
            a[23] = a[15].rotate_right(23);
            a[15] = a[4].rotate_left(27);
            a[4] = a[24].rotate_left(14);
            a[24] = a[21].rotate_left(2);
            a[21] = a[8].rotate_right(9);
            a[8] = a[16].rotate_right(19);
            a[16] = a[5].rotate_right(28);
            a[5] = a[3].rotate_left(28);
            a[3] = a[18].rotate_left(21);
            a[18] = a[17].rotate_left(15);
            a[17] = a[11].rotate_left(10);
            a[11] = a[7].rotate_left(6);
            a[7] = a[10].rotate_left(3);
            a[10] = c[1];
            // Chi
            for j in (0..=20).step_by(5) {
                c[0] = a[j] ^ (!a[j + 1] & a[j + 2]);
                c[1] = a[j + 1] ^ (!a[j + 2] & a[j + 3]);
                a[j + 2] ^= !a[j + 3] & a[j + 4];
                a[j + 3] ^= !a[j + 4] & a[j];
                a[j + 4] ^= !a[j] & a[j + 1];
                a[j] = c[0];
                a[j + 1] = c[1];
            }
            // Iota
            a[0] ^= Self::KECCAK_ROUND_CONSTANTS[round];
        }
    }

    #[inline]
    /// Convert 8 bytes at `offset` in `data` to an `u64` using little endian
    /// encoding.
    fn u64_from_le_slice(data: &[u8], offset: usize) -> u64 {
        let mut bytes = [0u8; size_of::<u64>()];
        bytes.copy_from_slice(&data[offset..offset + size_of::<u64>()]);
        u64::from_le_bytes(bytes)
    }
}

impl Digest for KeccakDigest {
    fn update(&mut self, data: &[u8]) {
        self.absorb_slice(data, 0, data.len());
    }

    fn output(&mut self, out: &mut [u8]) {
        self.squeeze(out);
    }

    fn reset(&mut self) {
        self.state.fill(0);
        self.data_queue.fill(0);
        self.bits_in_queue = 0;
        self.squeezing = false;
    }

    fn get_digest_size_bits(&self) -> usize {
        self.fixed_output_length
    }

    fn get_algorithm_name(&self) -> String {
        Self::ALGORITHM_NAME_PREFIX.to_string() + &self.get_digest_size_bits().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg0.pdf

    const TEST_VECTOR: &[(usize, &'static str, &'static str)] = &[
        (
            224,
            "",
            "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
        ),
        (
            224,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe",
        ),
        (
            224,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "c59d4eaeac728671c635ff645014e2afa935bebffdb5fbd207ffdeab",
        ),
        (
            256,
            "",
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        ),
        (
            256,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        ),
        (
            256,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d",
        ),
        (
            288,
            "",
            "6753e3380c09e385d0339eb6b050a68f66cfd60a73476e6fd6adeb72f5edd7c6f04a5d01",
        ),
        (
            288,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "0bbe6afae0d7e89054085c1cc47b1689772c89a41796891e197d1ca1b76f288154933ded",
        ),
        (
            288,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "82558a209b960ddeb531e6dcb281885b2400ca160472462486e79f071e88a3330a8a303d",
        ),
        (
            384,
            "",
            "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
        ),
        (
            384,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3",
        ),
        (
            384,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "9ad8e17325408eddb6edee6147f13856ad819bb7532668b605a24a2d958f88bd5c169e56dc4b2f89ffd325f6006d820b",
        ),
        (
            512,
            "",
            "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
        ),
        (
            512,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609",
        ),
        (
            512,
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760",
        ),
    ];

    #[test]
    fn test_vectors() {
        crate::test::common::init_logger();
        for (bit_length, msg, expected_digest_as_hex) in TEST_VECTOR.iter().cloned() {
            let hash_as_hex = &tyst_encdec::hex::encode(
                &KeccakDigest::new(bit_length).hash(&tyst_encdec::hex::decode(msg)),
            );
            assert_eq!(
                hash_as_hex.len()*4, bit_length,
                "Failed to generate the correct hash size for bit_length '{bit_length}' and messages '{msg}'."
            );
            assert_eq!(
                hash_as_hex, expected_digest_as_hex,
                "Failed to generate the correct hash for bit_length '{bit_length}' and messages '{msg}'."
            );
        }
    }
}
