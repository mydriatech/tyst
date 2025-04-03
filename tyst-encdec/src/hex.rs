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

//! Hexadecimal encoding and decoding

use crate::DecodingError;

#[doc(hidden)]
const CHARS_HEX_LOWERCASE: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Interpret as a hexidecimal string
pub trait ToHex {
    /// Return a hexidecimal `String`
    fn to_hex(&self) -> String;
}

impl ToHex for Vec<u8> {
    fn to_hex(&self) -> String {
        encode(self)
    }
}

impl ToHex for &[u8] {
    fn to_hex(&self) -> String {
        encode(self)
    }
}

/// Encode `data` as a newly allocated hexadecimal `String`
pub fn encode(data: &[u8]) -> String {
    let mut ret = String::with_capacity(data.len() * 2);
    for byte in data {
        ret.push(CHARS_HEX_LOWERCASE[usize::from((byte & 0xf0) >> 4)]);
        ret.push(CHARS_HEX_LOWERCASE[usize::from(byte & 0x0f)]);
    }
    ret
}

/** Decode hexadecimal representation in `data` as a newly allocated bytes Vec.

Assumes a well formed ascii hex string with even length
 */
pub fn decode(data: &str) -> Result<Vec<u8>, DecodingError> {
    if data.len() % 2 != 0 {
        DecodingError::with_msg("Even number of hex chars expected.");
    }
    let data_bytes = data.as_bytes();
    Ok((0..data.len())
        .step_by(2)
        .map(|i| {
            (quartet_from_char(data_bytes[i]).unwrap() << 4)
                | quartet_from_char(data_bytes[i + 1]).unwrap()
        })
        .collect::<Vec<_>>())
}

#[doc(hidden)]
#[inline]
fn quartet_from_char(ascii_char: u8) -> Result<u8, DecodingError> {
    match ascii_char {
        0x30..=0x39 => Ok(ascii_char - 0x30),
        0x41..=0x46 => Ok(ascii_char - 0x41 + 0x0a),
        0x61..=0x66 => Ok(ascii_char - 0x61 + 0x0a),
        c => Err(DecodingError::with_msg(&format!(
            "Char '{c:x}' is not valid hex."
        ))),
    }
}
