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

//! Example of using Message Authentication Code (MAC) REST API

use std::io::Read;
use tyst_core::encdec::base64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = std::env::args().nth(1) {
        println!("Available algorithms: {}", available_macs(&endpoint)?);
        let algorithm = "HMAC-SHA3-512";
        // An alternative here could be to use the endpoint
        //  "/api/v1/prng/{algorithm}/random/{byte_count}"
        // and take 72 bytes as key for HMAC-SHA3-512.
        let key_b64 = mac_keygen(&endpoint, algorithm).unwrap();
        let message = "This will be MACed!";
        println!(
            "{algorithm} of '{message}' is: {:x?}",
            mac(&endpoint, algorithm, &key_b64, message.as_bytes())?
        );
    } else {
        println!(
            "
Missing API endpoint. Run with:

    cargo run --example mac_rest_example -- 127.0.0.1:8084
"
        );
    }
    Ok(())
}

fn available_macs(endpoint: &str) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!("http://{}/api/v1/macs", endpoint))
        .call()?
        .into_string()?)
}

fn mac(
    endpoint: &str,
    algorithm: &str,
    key_b64: &str,
    message: &[u8],
) -> Result<Vec<u8>, ureq::Error> {
    // Size of HMAC is equal to the size of the hash-algo
    let mut bytes: Vec<u8> = Vec::with_capacity(512 / 8);
    ureq::post(&format!("http://{}/api/v1/mac/{algorithm}/mac", endpoint))
        .set("Accept", "application/json")
        .send_json(&serde_json::json!({
            "key": { "key_material_b64": key_b64 },
            "message_b64": base64::encode(message),
        }))?
        .into_reader()
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn mac_keygen(endpoint: &str, algorithm: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Size of HMAC is equal to the size of the hash-algo
    let res = ureq::post(&format!(
        "http://{}/api/v1/mac/{algorithm}/keygen",
        endpoint
    ))
    .set("Accept", "application/json")
    .call()?
    .into_string()?;
    let json = serde_json::from_str::<serde_json::Value>(&res)?;
    let key_b64 = json
        .get("key")
        .unwrap()
        .get("key_material_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    Ok(key_b64)
}
