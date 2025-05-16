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

//! Well-known Key Encapsulation Mechanism (KEM) Object Identifiers

// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
/// `2.16.840.1.101.3.4.4.1`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) kems(4) alg-ml-kem-512(1)
pub const ML_KEM_512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 1];
/// `2.16.840.1.101.3.4.4.2`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) kems(4) alg-ml-kem-768(2)
pub const ML_KEM_768: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 2];
/// `2.16.840.1.101.3.4.4.3`
///
// joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) kems(4) alg-ml-kem-1024(3)
pub const ML_KEM_1024: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 3];
