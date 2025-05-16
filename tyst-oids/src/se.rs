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

//! Well-known Signature Engine (SE) Object Identifiers

/// `2.16.840.1.101.3.4.3.17`
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3) ml-dsa-44(17)
pub const ML_DSA_44: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
/// `2.16.840.1.101.3.4.3.18`
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3) ml-dsa-65(18)
pub const ML_DSA_65: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
/// `2.16.840.1.101.3.4.3.18`
///
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3) ml-dsa-87(19)
pub const ML_DSA_87: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

// https://www.rfc-editor.org/rfc/rfc8410#section-9
/// `1.3.101.112`
///
// iso(1) identified-organization(3) thawte(101) id-Ed25519(112)
pub const EDDSA_ED25519: &[u32] = &[1, 3, 101, 112];

// https://www.ietf.org/rfc/rfc5758.html#section-3.2
/// `1.2.840.10045.4.3.2`
///
// iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA256 (2)
pub const ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
/// `1.2.840.10045.4.3.3`
///
// iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA384 (3)
pub const ECDSA_SHA384: &[u32] = &[1, 2, 840, 10045, 4, 3, 3];

/// `1.2.840.113549.1.1.10`
///
// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) rsassa-pss(10)
pub const RSASSA_PSS: &[u32] = &[1, 2, 840, 113549, 1, 1, 10];
/// `1.2.840.113549.1.1.11`
///
// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)
pub const RSASSA_PKCS1_V1_5_SHA_256: &[u32] = &[1, 2, 840, 113549, 1, 1, 11];
/// `1.2.840.113549.1.1.12`
///
// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha384WithRSAEncryption(12)
pub const RSASSA_PKCS1_V1_5_SHA_384: &[u32] = &[1, 2, 840, 113549, 1, 1, 12];
/// `1.2.840.113549.1.1.12`
///
// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha512WithRSAEncryption(13)
pub const RSASSA_PKCS1_V1_5_SHA_512: &[u32] = &[1, 2, 840, 113549, 1, 1, 13];
