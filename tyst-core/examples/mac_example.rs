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

//! Example of using Message Authentication Code (MAC) API

use tyst::Tyst;
use tyst::encdec::hex::ToHex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Available algorithms: {:?}",
        Tyst::instance().macs().get_algorithms()
    );
    let algorithm = "HMAC-SHA3-512";
    let mac_key = Tyst::instance()
        .macs()
        .by_name(algorithm)
        .unwrap()
        .generate_key();
    // Block size for HMAC-SHA3-512 is 72. Generate strongest possible key
    let mac_key_bytes = mac_key.try_as_bytes().unwrap();
    println!(
        "Generated key with {} bytes (hex): {}",
        mac_key_bytes.len(),
        mac_key_bytes.to_hex()
    );
    let message = "This will be MACed!";
    println!(
        "{algorithm} of '{message}' is: {:x?}",
        Tyst::instance()
            .macs()
            .by_name(algorithm)
            .unwrap()
            .mac(mac_key.as_ref(), message.as_bytes())
            .to_hex()
    );
    Ok(())
}
