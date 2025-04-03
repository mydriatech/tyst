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

//! Object Identifier String encode and decode.

pub use super::DecodingError;
use std::num::ParseIntError;

/// Convert a String of numbers with '.' as separator into a vector.
pub fn from_string(oid: &str) -> Result<Vec<u32>, DecodingError> {
    Ok(oid
        .split(".")
        .map(|part| {
            part.parse()
                .map_err(|e: ParseIntError| DecodingError::with_msg(&e.to_string()))
                .unwrap()
        })
        .collect::<Vec<u32>>())
}

/// Convert sequence of numbers into String using '.' as separator.
pub fn as_string(oid: &[u32]) -> String {
    oid.iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join(".")
}
