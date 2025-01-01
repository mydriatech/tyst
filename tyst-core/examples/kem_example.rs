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

//! Example of using Key Encapsulation Mechanism (KEM) API

use tyst_core::encdec::base64::ToBase64;
use tyst_core::traits::kem::ToEncapsulationKey;
use tyst_core::Tyst;
use tyst_traits::kem::KemCipherText;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Available algorithms: {:?}",
        Tyst::instance().kems().get_algorithms()
    );
    let algorithm = "ML-KEM-1024";
    let mut kem = Tyst::instance().kems().by_name(algorithm).unwrap();
    let (ek, dk) = kem.key_gen();
    println!(
        "Encapsulation key (b64, public): {}",
        ek.as_bytes().to_base64()
    );
    println!(
        "Decapsulation key (b64, secret): {}",
        dk.try_as_bytes().unwrap().to_base64()
    );
    let ek = ek.as_bytes();
    // Send encapsulation key to the "other party" and get the cipher text back
    let ct = {
        let ek = ek.to_decapsulation_key();
        let mut kem = Tyst::instance().kems().by_name(algorithm).unwrap();
        let (ct, ss) = kem.encapsulate(&ek).unwrap();
        println!(
            "Cipher text (b64, public):    {}",
            ct.as_bytes().to_base64()
        );
        println!(
            "Shared secret (b64, secret):  {} [remote]",
            ss.as_bytes().to_base64()
        );
        ct.as_bytes()
    };
    // Derive the same shared secret "locally" using the decapsulation key
    let ct = KemCipherText::from(ct);
    let ss = kem.decapsulate(&dk, &ct).unwrap();
    println!(
        "Shared secret (b64, secret):  {} [local]",
        ss.as_bytes().to_base64()
    );
    Ok(())
}
