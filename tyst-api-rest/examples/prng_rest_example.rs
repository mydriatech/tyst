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

//! Example of using Psuedo Random Number Generator (PRNG) REST API

use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = std::env::args().nth(1) {
        let algorithm = "default";
        let byte_count = 16;
        println!("Available algorithms: {}", available_prngs(&endpoint)?);
        println!(
            "{algorithm} generated {byte_count} bytes as hex: {}",
            prng_random_as_hex(&endpoint, algorithm, byte_count)?
        );
        println!(
            "{algorithm} generated {byte_count} bytes: {:x?}",
            prng_random(&endpoint, algorithm, byte_count)?
        );
    } else {
        println!(
            "
Missing API endpoint. Run with:

    cargo run --example prng_rest_example -- 127.0.0.1:8084
"
        );
    }
    Ok(())
}

fn available_prngs(endpoint: &str) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!("http://{}/api/v1/prngs", endpoint))
        .call()?
        .into_string()?)
}

fn prng_random(endpoint: &str, algorithm: &str, byte_count: usize) -> Result<Vec<u8>, ureq::Error> {
    let mut bytes: Vec<u8> = Vec::with_capacity(byte_count);
    ureq::get(&format!(
        "http://{}/api/v1/prng/{algorithm}/random/{byte_count}",
        endpoint
    ))
    .set("Accept", "application/octet-stream")
    .call()?
    .into_reader()
    .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn prng_random_as_hex(
    endpoint: &str,
    algorithm: &str,
    byte_count: usize,
) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!(
        "http://{}/api/v1/prng/{algorithm}/random/{byte_count}",
        endpoint
    ))
    .call()?
    .into_string()?)
}
