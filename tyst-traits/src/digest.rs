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

//! Message Digest (hash) traits and structs

/// Message Digest (hash)
pub trait Digest: Send {
    /// Ingest/absorb the provided `data` into the message digest.
    fn update(&mut self, data: &[u8]);

    /// Write the output state of the message digest (the "hash") to `out`.
    fn output(&mut self, out: &mut [u8]);

    /// Write the output state of the message digest (the "hash") to `out`
    /// and reset the message digest.
    fn finalize(&mut self, out: &mut [u8]) {
        self.output(out);
        self.reset();
    }

    /// Reset the message digest to the initial state.
    fn reset(&mut self);

    /// Return the size of the message digest (the "hash") output state in bits.
    fn get_digest_size_bits(&self) -> usize;

    /// Return human readable identifier of the crypto algorithm.
    fn get_algorithm_name(&self) -> String;

    /// Convinience method for ingesting the provided data and returning the
    /// output state (hash) in a single invocation.
    fn hash(&mut self, data: &[u8]) -> Vec<u8> {
        self.update(data);
        let mut out = vec![0u8; self.get_digest_size_bits() >> 3];
        self.finalize(&mut out);
        out
    }
}

/** Builder style Message Digest (hash) parameters.

### Example

```
# use tyst_traits::digest::DigestParams;
DigestParams::default()
    .set_output_bits(768);
```
*/
#[derive(Default)]
pub struct DigestParams {
    output_bits: Option<usize>,
}

impl DigestParams {
    /// Set the output size for Extendable Output Function (XOF) algorithms.
    pub fn set_output_bits(mut self, output_bits: usize) -> Self {
        self.output_bits = Some(output_bits);
        self
    }

    /// Get the output size for Extendable Output Function (XOF) algorithms.
    #[doc(hidden)]
    pub fn output_bits(&self) -> Option<usize> {
        self.output_bits
    }
}
