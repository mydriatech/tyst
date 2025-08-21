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

//! Example of using Psuedo Random Number Generator (PRNG) API

use tyst::Tyst;
use tyst::encdec::hex::ToHex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    {
        // Generate random using a specific algorithm and instance
        let algorithm = "HMAC-DRBG-SHA3-512";
        println!(
            "Available algorithms: {:?}",
            Tyst::instance().prngs().get_algorithms()
        );
        let mut prng = Tyst::instance().prngs().by_name(algorithm).unwrap();
        let mut random_bytes = [0u8; 32];
        prng.next_bytes(&mut random_bytes);
        println!(
            "{algorithm} generated {} bytes as hex: {}",
            random_bytes.len(),
            random_bytes.as_slice().to_hex()
        );
    }
    {
        // Just get some random using the best of breed algorithm according to the library
        let mut random_bytes = [0u8; 32];
        Tyst::instance().prng_fill_with_random(None, &mut random_bytes);
        println!(
            "Default algorithm generated {} bytes as hex:  {}",
            random_bytes.len(),
            random_bytes.as_slice().to_hex()
        );
    }
    Ok(())
}
