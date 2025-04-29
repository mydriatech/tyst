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

//! Miscellaneous cryptographic primitive REST API resources

use actix_web::error::ErrorBadRequest;
use actix_web::http::StatusCode;
use actix_web::post;
use actix_web::web::Json;
use actix_web::HttpResponse;
use actix_web::Responder;
use actix_web::Result;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use tyst::Tyst;
use utoipa::ToSchema;

#[serde_as]
#[derive(ToSchema, Deserialize)]
pub struct KdfRequest {
    #[serde_as(as = "Base64")]
    pub password_b64: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub salt_b64: Vec<u8>,
    pub iterations: u64,
    pub output_len: u64,
}

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct KdfResponse {
    #[serde_as(as = "Base64")]
    pub derived_key_b64: Vec<u8>,
}

/// PBKDF2
///
/// Password-Based Key Derivation Function 2 (PBKDF2).
#[utoipa::path(
    request_body = inline(KdfRequest),
    responses(
        (status = 200, description = "Success", body = inline(KdfResponse), content_type = "application/json",),
        (status = 404, description = "Bad request. Too many iterations or too large output requested."),
        (status = 404, description = "Fail"),
    ),
)]
#[post("/misc/PBKDF2/derive")]
pub async fn pbkdf2_derive(request: Json<KdfRequest>) -> Result<impl Responder> {
    if request.iterations > 16384 {
        return Ok(HttpResponse::build(StatusCode::BAD_REQUEST).finish());
    }
    if request.output_len > 65536 {
        return Ok(HttpResponse::build(StatusCode::BAD_REQUEST).finish());
    }
    // TODO: Make this a query param (instead of hard-coding HMAC-SHA3-512)
    if let Some(prf) = Tyst::instance().macs().by_name("HMAC-SHA3-512") {
        let response = KdfResponse {
            derived_key_b64: tyst::misc::Pbkdf2::new(
                &request.salt_b64,
                usize::try_from(request.iterations).unwrap(),
                usize::try_from(request.output_len).unwrap(),
                prf,
            )
            .derive_key(&request.password_b64),
        };

        Ok(HttpResponse::build(StatusCode::OK)
            .body(serde_json::to_string_pretty(&response).unwrap()))
    } else {
        Err(ErrorBadRequest(
            "Unable to find any matching MAC to use as PRF.",
        ))
    }
}
