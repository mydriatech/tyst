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

//! Encoding and decoding errors.

use std::error::Error;
use std::fmt;

/// Decoding error
#[derive(Debug, Default)]
pub struct DecodingError {
    msg: Option<String>,
}

impl DecodingError {
    /// Create a new instance with an error message.
    pub fn with_msg(msg: &str) -> Self {
        Self {
            msg: Some(msg.to_string()),
        }
    }
}

impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "DecodingError {}", msg)
        } else {
            write!(f, "DecodingError")
        }
    }
}

impl Error for DecodingError {}
