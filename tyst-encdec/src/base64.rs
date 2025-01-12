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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        //crate::test::common::init_logger();
        let expected = "TXlkcmlhVGVjaCBBQgo=";
        assert_eq!(
            encode(b"MydriaTech AB\n".as_slice()).as_str(),
            expected,
            "Basic base64 encoder is broken."
        );
    }
}
