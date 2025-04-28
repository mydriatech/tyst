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

//! Example of using Key Derivation Function (KDF) API

use tyst::encdec::hex::ToHex;
use tyst::Tyst;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Available algorithms: {:?}",
        Tyst::instance().kdfs().get_algorithms()
    );
    let key_len = 64;
    let mut derived_key = vec![0u8; key_len];
    Tyst::instance().kdfs().by_name("PBKDF2").unwrap().derive(
        b"password",
        b"salt should be as long as the HMAC output function",
        123,
        &mut derived_key,
    );
    println!(
        "Derived a key with {} bytes (hex): {}",
        key_len,
        derived_key.to_hex()
    );
    Ok(())
}
