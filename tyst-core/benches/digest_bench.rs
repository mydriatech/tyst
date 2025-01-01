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

//! Benchmark of message digest (hash) implementations

use bencher::benchmark_group;
use bencher::Bencher;
use core::hint::black_box;
use tyst_core::Tyst;

fn sha3<const S: usize, const N: usize>(bench: &mut Bencher) {
    let data = [0u8; N];
    let algorithm_name = "SHA3-".to_string() + &S.to_string();
    bench.iter(|| {
        black_box(
            Tyst::instance()
                .digests()
                .by_name(&algorithm_name)
                .unwrap()
                .hash(&data),
        );
    });
    bench.bytes = u64::try_from(N).unwrap();
}

fn shake<const S: usize, const N: usize>(bench: &mut Bencher) {
    let data = [0u8; N];
    let algorithm_name = "SHAKE".to_string() + &S.to_string();
    bench.iter(|| {
        black_box(
            Tyst::instance()
                .digests()
                .by_name(&algorithm_name)
                .unwrap()
                .hash(&data),
        );
    });
    bench.bytes = u64::try_from(N).unwrap();
}

benchmark_group!(digests,
    sha3<256, 1024>, sha3<256, {32*1024}>,
    sha3<384, 1024>, sha3<384, {32*1024}>,
    sha3<512, 1024>, sha3<512, {32*1024}>,
    shake<128, 1024>, shake<128, {32*1024}>,
    shake<256, 1024>, shake<256, {32*1024}>,
);
