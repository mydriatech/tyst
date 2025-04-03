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

//! Example of using Key Encapsulation Mechanism (KEM) REST API

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = std::env::args().nth(1) {
        println!("Available algorithms: {}", available_kems(&endpoint)?);
        let algorithm = "ML-KEM-768";
        let (ek_b64, dk_b64) = kem_keygen(&endpoint, algorithm)?;
        println!("Encapsulatrion key (b64, public):  {ek_b64}");
        println!("Decapsulatrion key (b64, private): {dk_b64}");
        // Send encapsulation key to the "other party" and get the cipher text back
        let ct_b64 = {
            let (ct_b64, ss_b64) = kem_encapsulate(&endpoint, algorithm, ek_b64)?;
            println!("Cipher text (b64, public):    {ct_b64}");
            println!("Shared secret (b64, private): {ss_b64}");
            ct_b64
        };
        // Derive the same shared secret "locally" using the decapsulation key
        let ss_b64 = kem_decapsulate(&endpoint, algorithm, dk_b64, ct_b64)?;
        println!("Shared secret (b64, private): {ss_b64}");
    } else {
        println!(
            "
Missing API endpoint. Run with:

    cargo run --example kem_rest_example -- 127.0.0.1:8084
"
        );
    }
    Ok(())
}

fn available_kems(endpoint: &str) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!("http://{}/api/v1/kems", endpoint))
        .call()?
        .body_mut()
        .read_to_string()?)
}

fn kem_keygen(
    endpoint: &str,
    algorithm: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let res = ureq::post(&format!(
        "http://{}/api/v1/kem/{algorithm}/keygen",
        endpoint
    ))
    .header("Accept", "application/json")
    .send_empty()?
    .body_mut()
    .read_to_string()?;
    let json = serde_json::from_str::<serde_json::Value>(&res)?;
    let dk_b64 = json
        .get("decapsulation_key")
        .unwrap()
        .get("key_material_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let ek_b64 = json
        .get("encapsulation_key_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    Ok((ek_b64, dk_b64))
}

fn kem_encapsulate(
    endpoint: &str,
    algorithm: &str,
    ek_b64: String,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let res = ureq::post(&format!(
        "http://{}/api/v1/kem/{algorithm}/encapsulate",
        endpoint
    ))
    .header("Accept", "application/json")
    .send_json(&serde_json::json!({
        "encapsulation_key_b64": ek_b64,
    }))?
    .body_mut()
    .read_to_string()?;
    let json = serde_json::from_str::<serde_json::Value>(&res)?;
    let ct_b64 = json
        .get("cipher_text_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let ss_b64 = json
        .get("shared_secret_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    Ok((ct_b64, ss_b64))
}

fn kem_decapsulate(
    endpoint: &str,
    algorithm: &str,
    dk_b64: String,
    ct_b64: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let res = ureq::post(&format!(
        "http://{}/api/v1/kem/{algorithm}/decapsulate",
        endpoint
    ))
    .header("Accept", "application/json")
    .send_json(&serde_json::json!({
        "decapsulation_key": {
            "key_material_b64": dk_b64
        },
        "cipher_text_b64": ct_b64,
    }))?
    .body_mut()
    .read_to_string()?;
    let json = serde_json::from_str::<serde_json::Value>(&res)?;
    let ss_b64 = json
        .get("shared_secret_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    Ok(ss_b64)
}
