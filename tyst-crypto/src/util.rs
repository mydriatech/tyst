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

//! Utility functions used by algorithm implementations.

/// (Maybe) unoptimized constant time comparision of two slices.
///
/// This relies on [std::hint::black_box]. "This ... does not offer any
/// guarantees for cryptographic or security purposes."
///
/// Inspired by
/// [org.bouncycastle.util.Arrays.constantTimeAreEqual()](https://github.com/bcgit/bc-java/blob/b6cb37c83caabba2f3a6b87787dd08a51124dffe/core/src/main/java/org/bouncycastle/util/Arrays.java#L91)
pub fn maybe_constant_time_equals(expected: &[u8], supplied: &[u8]) -> bool {
    // Hint, but without any guarantees that this code wont be optimized
    std::hint::black_box({
        let len = if expected.len() < supplied.len() {
            expected.len()
        } else {
            supplied.len()
        };
        let mut none_equal = expected.len() ^ supplied.len();
        for i in 0..len {
            none_equal |= (expected[i] ^ supplied[i]) as usize;
        }
        #[allow(clippy::eq_op)]
        for byte in supplied {
            none_equal |= (byte ^ byte) as usize;
        }
        none_equal == 0
    })
}

#[inline]
/// Externally implemented constant time comparision of two slices.
///
/// This uses [constant_time_eq](https://docs.rs/constant_time_eq/latest/constant_time_eq/fn.constant_time_eq.html)
/// which relies on unsafe Rust.
pub fn external_constant_time_equals(expected: &[u8], supplied: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(expected, supplied)
}
