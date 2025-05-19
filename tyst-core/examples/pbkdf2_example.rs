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

//! Example of using Password-Based Key Derivation Function 2 (PBKDF2).

use tyst::Tyst;
use tyst::encdec::hex::ToHex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prf = Tyst::instance().macs().by_name("HMAC-SHA3-512").unwrap();
    let mut pbkdf2 = tyst::misc::Pbkdf2::new(
        b"salt should be as long as the HMAC output function",
        123,
        64,
        prf,
    );
    let derived_key = pbkdf2.derive_key(b"password");
    println!(
        "Derived a key with {} bytes (hex): {}",
        derived_key.len(),
        derived_key.to_hex()
    );
    Ok(())
}
