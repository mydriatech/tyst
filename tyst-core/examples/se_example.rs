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

use tyst::Tyst;
use tyst::encdec::base64::ToBase64;
use tyst::traits::se::ToPrivateKey;
use tyst::traits::se::ToPublicKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Available algorithms: {:?}",
        Tyst::instance().ses().get_algorithms()
    );
    let algorithm = "ML-DSA-87";
    let mut se = Tyst::instance().ses().by_name(algorithm).unwrap();
    let (pub_key, priv_key) = se.generate_key_pair();
    let pub_key_bytes = pub_key.try_as_spki().unwrap();
    println!("Public key (b64, public):   {}", pub_key_bytes.to_base64());
    let priv_key_bytes = priv_key.try_as_bytes().unwrap();
    println!("Private key (b64, private): {}", priv_key_bytes.to_base64());
    // Serialize and deserialize, just to show how..
    let priv_key = priv_key_bytes.to_private_key();
    let pub_key = pub_key_bytes.to_public_key();
    // Sign a message
    let message = "This will be signed!";
    let signature = se.sign(priv_key.as_ref(), message.as_bytes()).unwrap();
    println!("Message (public):        {message}");
    println!("Signature (b64, public): {}", signature.to_base64());
    // Verify signature
    let signature_ok = se.verify(pub_key.as_ref(), &signature, &message.as_bytes());
    println!("Signature verified:      {signature_ok}");
    Ok(())
}
