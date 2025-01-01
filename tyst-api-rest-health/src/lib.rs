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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

// Eclipse MicroProfile Health implementation for Actix Web

pub mod health_resources;

/// Represents the current state of the application.
pub trait AppHealth: Send + Sync {
    /// Return `true` when the application is initialized.
    ///
    /// The default implementation of returns `true`.
    fn is_health_started(&self) -> bool {
        true
    }

    /// Return true when the application is ready to process requests.
    ///
    /// The default implementation of returns `true`.
    fn is_health_ready(&self) -> bool {
        true
    }

    /// Return true when the application if working as expected and does not
    /// need to be restarted.
    ///
    /// The default implementation of returns `true`.
    fn is_health_live(&self) -> bool {
        true
    }
}
