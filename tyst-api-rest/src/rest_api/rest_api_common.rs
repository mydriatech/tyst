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

//! Common utility functions for REST API resources

use actix_web::error::ErrorBadRequest;
use actix_web::web::Bytes;
use actix_web::web::BytesMut;
use actix_web::web::Payload;
use actix_web::Error;
use actix_web::HttpRequest;
use actix_web::Result;
use futures::StreamExt;
use serde::Deserialize;
use serde::Serialize;
use serde_with::base64::Base64;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use tyst_core::traits::factory::AlgorithmMetaData;
use utoipa::ToSchema;

pub const MAX_DOCUMENT_SIZE: usize = 5 * 1024 * 1024;

#[serde_as]
#[skip_serializing_none]
#[derive(ToSchema, Deserialize, Serialize)]
pub struct ConfinedKeyMaterial {
    /// Type of confinement. E.g. "soft".
    pub confinement_type: Option<String>,
    /// Identifier used by provider to locate the correct confinement.
    pub confinement_id: Option<String>,
    /// Identifier used by provider to locate the correct object.
    pub object_reference: Option<String>,
    /// Base64 encoded key material
    #[serde_as(as = "Base64")]
    pub key_material_b64: Vec<u8>,
}

#[skip_serializing_none]
#[derive(ToSchema, Serialize)]
pub struct AlgorithmMetaDataItem {
    name: String,
    provider_id: String,
    confinement_type: String,
    oid: Option<String>,
}

impl From<AlgorithmMetaData> for AlgorithmMetaDataItem {
    fn from(value: AlgorithmMetaData) -> Self {
        Self {
            name: value.name().to_owned(),
            provider_id: value.provider_id().to_owned(),
            confinement_type: value.confinement_type().to_owned(),
            oid: value.oid().map(|oid| oid.to_string()),
        }
    }
}

pub async fn get_bytes_from_request(
    mut payload: Payload,
    http_request: &HttpRequest,
    max_size_bytes: usize,
) -> Result<Bytes, Error> {
    let http_headers = http_request.headers();
    let content_length_estimate = http_headers
        .get("content-length")
        .and_then(|header_value| header_value.to_str().ok())
        .and_then(|header_value_str| header_value_str.parse::<usize>().ok())
        .unwrap_or(1024);
    if content_length_estimate > max_size_bytes {
        return Err(ErrorBadRequest("overflow"));
    }
    // TODO: Can we use stack alloc here for small requests and overflow to heap?
    let mut body = BytesMut::with_capacity(content_length_estimate);
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > max_size_bytes {
            return Err(ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}
