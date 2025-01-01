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

//! Benchmark of signature engine (SE) ML-DSA implementation

use bencher::benchmark_group;
use bencher::Bencher;
use core::hint::black_box;
use tyst_core::Tyst;

fn ml_dsa_keygen(bench: &mut Bencher) {
    bench.iter(|| {
        black_box(
            Tyst::instance()
                .ses()
                .by_name("ML-DSA-87")
                .unwrap()
                .generate_key_pair(),
        );
    })
}

fn ml_dsa_sign(bench: &mut Bencher) {
    let (_public_key, private_key) = Tyst::instance()
        .ses()
        .by_name("ML-DSA-87")
        .unwrap()
        .generate_key_pair();
    //let private_key = hex::decode(&"").to_private_key();
    let message = b"This will be signed over and over again.";
    bench.iter(|| {
        black_box(
            Tyst::instance()
                .ses()
                .by_name("ML-DSA-87")
                .unwrap()
                .sign(&private_key, message),
        );
    })
}

fn ml_dsa_verify(bench: &mut Bencher) {
    let (public_key, private_key) = Tyst::instance()
        .ses()
        .by_name("ML-DSA-87")
        .unwrap()
        .generate_key_pair();
    let message = b"This will be signed once, but verified over and over again.";
    let signature = Tyst::instance()
        .ses()
        .by_name("ML-DSA-87")
        .unwrap()
        .sign(&private_key, message)
        .unwrap();
    bench.iter(|| {
        black_box(Tyst::instance().ses().by_name("ML-DSA-87").unwrap().verify(
            &public_key,
            &signature,
            message,
        ));
    })
}

benchmark_group!(ml_dsa, ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify);
