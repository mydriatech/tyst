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

//! Example of using message digest (hash)

use tyst::Tyst;
use tyst::encdec::hex::ToHex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = "SHA3-384";
    println!(
        "{algorithm} is available: {}",
        Tyst::instance()
            .digests()
            .get_algorithms()
            .contains(&algorithm.to_string())
    );
    let message = "This will be hashed!";
    println!(
        "{algorithm} hash of '{message}' as hex:   {}",
        Tyst::instance()
            .digests()
            .by_name(algorithm)
            .unwrap()
            .hash(message.as_bytes())
            .to_hex()
    );
    Ok(())
}
