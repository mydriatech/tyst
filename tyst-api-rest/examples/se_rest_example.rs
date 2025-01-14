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

//! Example of using Signature Engine REST API

use tyst::encdec::base64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = std::env::args().nth(1) {
        println!("Available algorithms: {}", available_ses(&endpoint)?);
        let algorithm = "ML-DSA-87";
        let (pub_key_b64, priv_key_b64) = se_keygen(&endpoint, algorithm)?;
        println!("Public key (b64, public):   {pub_key_b64}");
        println!("Private key (b64, private): {priv_key_b64}");
        // Sign a message
        let message = "This will be signed!";
        let message_b64 = base64::encode(message.as_bytes());
        let signature_b64 = se_sign(&endpoint, algorithm, &priv_key_b64, &message_b64)?;
        println!("Message (public):        {message}");
        println!("Signature (b64, public): {signature_b64}");
        // Verify signature
        let signature_ok = se_verify(
            &endpoint,
            algorithm,
            &pub_key_b64,
            &signature_b64,
            &message_b64,
        )?;
        println!("Signature verified:      {signature_ok}");
    } else {
        println!(
            "
Missing API endpoint. Run with:

    cargo run --example se_rest_example -- 127.0.0.1:8084
"
        );
    }
    Ok(())
}

fn available_ses(endpoint: &str) -> Result<String, ureq::Error> {
    Ok(ureq::get(&format!("http://{}/api/v1/ses", endpoint))
        .call()?
        .into_string()?)
}

fn se_keygen(
    endpoint: &str,
    algorithm: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Size of HMAC is equal to the size of the hash-algo
    let res = ureq::post(&format!("http://{}/api/v1/se/{algorithm}/keygen", endpoint))
        .set("Accept", "application/json")
        .call()?
        .into_string()?;
    let json = serde_json::from_str::<serde_json::Value>(&res)?;
    let priv_key_b64 = json
        .get("private_key")
        .unwrap()
        .get("key_material_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let pub_key_b64 = json
        .get("public_key_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    Ok((pub_key_b64, priv_key_b64))
}

fn se_sign(
    endpoint: &str,
    algorithm: &str,
    priv_key_b64: &str,
    message_b64: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Size of HMAC is equal to the size of the hash-algo
    let res = ureq::post(&format!("http://{}/api/v1/se/{algorithm}/sign", endpoint))
        .set("Accept", "application/json")
        .send_json(&serde_json::json!({
            "private_key": {
                "key_material_b64": priv_key_b64.to_string(),
            },
            "message_b64": message_b64.to_string(),
        }))?
        .into_string()?;
    let json = serde_json::from_str::<serde_json::Value>(&res)?;
    let signature_b64 = json
        .get("signature_b64")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    Ok(signature_b64)
}

fn se_verify(
    endpoint: &str,
    algorithm: &str,
    pub_key_b64: &str,
    siganture_b64: &str,
    message_b64: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(
        ureq::post(&format!("http://{}/api/v1/se/{algorithm}/verify", endpoint))
            //.set("Accept", "application/json")
            .send_json(&serde_json::json!({
                "public_key_b64": pub_key_b64.to_string(),
                "signature_b64": siganture_b64.to_string(),
                "message_b64": message_b64.to_string(),
            }))?
            .status()
            == 204,
    )
}
