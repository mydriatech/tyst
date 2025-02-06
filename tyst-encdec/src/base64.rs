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

//! [RFC4648](https://datatracker.ietf.org/doc/html/rfc4648#section-4) base 64
//! encoding

#[doc(hidden)]
const CHAR_PADDING: char = '=';

#[doc(hidden)]
const CHARS_BASE64: [char; 64 + 1] = [
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
    'G',
    'H',
    'I',
    'J',
    'K',
    'L',
    'M',
    'N',
    'O',
    'P',
    'Q',
    'R',
    'S',
    'T',
    'U',
    'V',
    'W',
    'X',
    'Y',
    'Z',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '+',
    '/',
    CHAR_PADDING,
];

/// Interpret as a Base64 string
pub trait ToBase64 {
    /// Return a Base64 `String`
    fn to_base64(&self) -> String;
}

impl ToBase64 for Vec<u8> {
    fn to_base64(&self) -> String {
        encode(self)
    }
}

impl ToBase64 for &[u8] {
    fn to_base64(&self) -> String {
        encode(self)
    }
}

/// Base64 encode using standard characters (`A-Z-a-z0-9+/`) and padding (`=`).
pub fn encode(data: &[u8]) -> String {
    // each 8-bit char represents 6 bits of the original data
    let mut ret = String::with_capacity(data.len() * 8 / 6);
    for offset in (0..data.len()).step_by(3) {
        // Untouched output will be converted to the padding char
        let mut out = [64; 4];
        for (i, byte) in data[offset..].iter().take(3).enumerate() {
            match i {
                0 => {
                    // 0xfc: 1111 1100
                    out[0] = (byte & 0xfc) >> 2;
                    // 0x03: 0000 0011
                    out[1] = (byte & 0x03) << 4;
                }
                1 => {
                    // 0xf0: 1111 0000
                    out[1] |= (byte & 0xf0) >> 4;
                    // 0xf0: 0000 1111
                    out[2] = (byte & 0x0f) << 2;
                }
                2 => {
                    // 0xc0: 1100 0000
                    out[2] |= (byte & 0xc0) >> 6;
                    // 0xc0: 0011 1111
                    out[3] = byte & 0x3f;
                }
                _ => panic!(),
            }
        }
        for byte in out {
            ret.push(CHARS_BASE64[byte as usize]);
        }
    }
    ret
}

/// Base64 decode using standard characters (`A-Z-a-z0-9+/`) and padding (`=`).
pub fn decode(data: &str) -> Vec<u8> {
    // Alloc max use
    let data = data.trim().as_bytes();
    let mut ret = Vec::with_capacity(data.len() * 6 / 8);
    // each 8-bit char represents 6 bits of the original data
    for offset in (0..data.len()).step_by(4) {
        let mut out = [64; 3];
        for (i, byte) in data[offset..].iter().take(4).enumerate() {
            let byte = match byte {
                // +
                0x2b => 62,
                // /
                0x2f => 63,
                // 0-9
                0x30..=0x39 => byte - 0x30 + 26 * 2,
                // =
                0x3d => 0,
                // A-Z
                0x41..=0x5a => byte - 0x41,
                // a-z
                0x61..=0x7a => byte - 0x61 + 26,
                // Unknown garbage
                c => panic!("Unknown garbage in input: '{c}'"),
            };
            match i {
                0 => {
                    // 0x3f: 0011 1111
                    out[0] = byte << 2;
                }
                1 => {
                    // 0x30: 0011 0000
                    out[0] |= (byte & 0x30) >> 4;
                    // 0x0f: 0000 1111
                    out[1] = (byte & 0x0f) << 4;
                }
                2 => {
                    // 0x3c: 0011 1100
                    out[1] |= (byte & 0x3c) >> 2;
                    // 0x03: 0000 0011
                    out[2] = (byte & 0x03) << 6;
                }
                3 => {
                    // 0x3f: 0011 1111
                    out[2] |= byte;
                }
                _ => panic!(),
            }
        }
        ret.extend(out);
    }
    // Remove padding from output
    if data.len() > 1 && data[data.len() - 1] == 0x3d {
        ret.pop();
        if data.len() > 2 && data[data.len() - 2] == 0x3d {
            ret.pop();
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check_encode() {
        //crate::test::common::init_logger();
        let expected = "TXlkcmlhVGVjaCBBQgo=";
        assert_eq!(
            encode(b"MydriaTech AB\n".as_slice()).as_str(),
            expected,
            "Basic base64 encoder is broken."
        );
    }

    #[test]
    fn sanity_check_decode() {
        //crate::test::common::init_logger();
        let expected = b"MydriaTech AB\n".as_slice();
        assert_eq!(
            &decode("TXlkcmlhVGVjaCBBQgo="),
            expected,
            "Basic base64 decoder is broken."
        );
    }
}
