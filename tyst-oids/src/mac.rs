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

//! Well-known Message Authentication Code (MAC) Object Identifiers

/*
[RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) Identifiers and Test
Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
*/
/// `1.2.840.113549.2.8`
///
/// iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) hmacWithSHA224(8)
pub const HMAC_SHA_224: &[u32] = &[1, 2, 840, 113549, 2, 8];
/// `1.2.840.113549.2.9`
///
/// iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) hmacWithSHA256(9)
pub const HMAC_SHA_256: &[u32] = &[1, 2, 840, 113549, 2, 9];
/// `1.2.840.113549.2.10`
///
/// iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) hmacWithSHA384(10)
pub const HMAC_SHA_384: &[u32] = &[1, 2, 840, 113549, 2, 10];
/// `1.2.840.113549.2.11`
///
/// iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) hmacWithSHA512(11)
pub const HMAC_SHA_512: &[u32] = &[1, 2, 840, 113549, 2, 11];

/// `2.16.840.1.101.3.4.2.13`
///
/// NOTE: SHA3-224 should not be used after 2023.
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2) hmacWithSHA3-224(13)
pub const HMAC_SHA3_224: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 13];
/// `2.16.840.1.101.3.4.2.14`
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2) hmacWithSHA3-256(14)
pub const HMAC_SHA3_256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 14];
/// `2.16.840.1.101.3.4.2.15`
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2) hmacWithSHA3-384(15)
pub const HMAC_SHA3_384: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 15];
/// `2.16.840.1.101.3.4.2.16`
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2) hmacWithSHA3-512(16)
pub const HMAC_SHA3_512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 16];
