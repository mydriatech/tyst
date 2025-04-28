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

//! Example of using Key Derivation Function (KDF) REST API

use tyst::encdec::{base64, hex::ToHex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = std::env::args().nth(1) {
        println!("Available algorithms: {}", available_kdfs(&endpoint)?);
        let algorithm = "PBKDF2";
        let password = b"badpassword";
        let salt = b"tooshortsalt";
        println!(
            "{algorithm} derived key '{}'",
            derive_key(&endpoint, algorithm, password, salt, 1234, 32)?.to_hex()
        );
    } else {
        println!(
            "
Missing API endpoint. Run with:

    cargo run --example kdf_rest_example -- 127.0.0.1:8084
"
        );
    }
    Ok(())
}

fn available_kdfs(endpoint: &str) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!("http://{}/api/v1/kdfs", endpoint))
        .call()?
        .body_mut()
        .read_to_string()?)
}

fn derive_key(
    endpoint: &str,
    algorithm: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    output_len: u64,
) -> Result<Vec<u8>, ureq::Error> {
    // Size of HMAC is equal to the size of the hash-algo
    Ok(ureq::post(&format!(
        "http://{}/api/v1/kdf/{algorithm}/derive",
        endpoint
    ))
    .header("Accept", "application/json")
    .send_json(&serde_json::json!({
        "password_b64": base64::encode(password),
        "salt_b64": base64::encode(salt),
        "iterations": iterations,
        "output_len": output_len,
    }))?
    .body_mut()
    .read_to_vec()?)
}
