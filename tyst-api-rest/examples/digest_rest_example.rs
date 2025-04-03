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

//! Example of using message digest REST API

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = std::env::args().nth(1) {
        let algorithm = "SHA3-384";
        println!(
            "{algorithm} is available: {}",
            available_digests(&endpoint)?.contains(algorithm)
        );
        let message = "This will be hashed!";
        println!(
            "{algorithm} hash of '{message}' as hex:   {}",
            hash_as_hex(&endpoint, algorithm, message.as_bytes())?
        );
        println!(
            "{algorithm} hash of '{message}' as bytes: {:x?}",
            hash(&endpoint, algorithm, message.as_bytes())?
        );
    } else {
        println!(
            "
Missing API endpoint. Run with:

    cargo run --example digest_rest_example -- 127.0.0.1:8084
"
        );
    }
    Ok(())
}

fn available_digests(endpoint: &str) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!("http://{}/api/v1/digests", endpoint))
        .call()?
        .body_mut()
        .read_to_string()?)
}

fn hash(endpoint: &str, algorithm: &str, message: &[u8]) -> Result<Vec<u8>, ureq::Error> {
    Ok(
        ureq::post(&format!("http://{}/api/v1/digest/{algorithm}", endpoint))
            .header("Accept", "application/octet-stream")
            .send(message)?
            .body_mut()
            .read_to_vec()?,
    )
}

fn hash_as_hex(endpoint: &str, algorithm: &str, message: &[u8]) -> Result<String, ureq::Error> {
    Ok(
        ureq::post(&format!("http://{}/api/v1/digest/{algorithm}", endpoint))
            .send(message)?
            .body_mut()
            .read_to_string()?,
    )
}
