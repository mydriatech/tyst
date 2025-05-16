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

//! Well-known Message Digest (hash) Object Identifiers

/// `1.3.14.3.2.26`
///
/// iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)
pub const SHA_1: &[u32] = &[1, 3, 14, 3, 2, 26];

/// `2.16.840.1.101.3.4.2.1`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha256(1)
pub const SHA_256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
/// `2.16.840.1.101.3.4.2.2`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha384(2)
pub const SHA_384: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
/// `2.16.840.1.101.3.4.2.3`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha512(3)
pub const SHA_512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
/// `2.16.840.1.101.3.4.2.4`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha224(4)
pub const SHA_224: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 4];
/// `2.16.840.1.101.3.4.2.5`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha512-224(5)
pub const SHA_512_224: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 5];
/// `2.16.840.1.101.3.4.2.6`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha512-256(6)
pub const SHA_512_256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 6];

// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
/// `2.16.840.1.101.3.4.2.7`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-224(7)
pub const SHA3_224: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 7];
/// `2.16.840.1.101.3.4.2.8`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-256(8)
pub const SHA3_256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 8];
/// `2.16.840.1.101.3.4.2.9`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-384(9)
pub const SHA3_384: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 9];
/// `2.16.840.1.101.3.4.2.10`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha3-512(10)
pub const SHA3_512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 10];
/// `2.16.840.1.101.3.4.2.11`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) shake128(11)
pub const SHAKE128: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 11];
/// `2.16.840.1.101.3.4.2.12`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) shake256(12)
pub const SHAKE256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 12];

// https://www.rfc-editor.org/rfc/rfc4055#section-2.2
/// `1.2.840.113549.1.1.8`
///
// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) mgf1(8)
pub const MGF1: &[u32] = &[1, 2, 840, 113549, 1, 1, 8];
