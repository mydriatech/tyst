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

//! Key Derivation Function (KDF) REST API resources

use super::rest_api_common::AlgorithmMetaDataItem;
use actix_web::error::ErrorBadRequest;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::post;
use actix_web::web::Json;
use actix_web::web::Path;
use actix_web::Error;
use actix_web::HttpResponse;
use actix_web::Responder;
use actix_web::Result;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use tyst::traits::kdf::KdfParams;
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

/// List available KDF algorithms
///
/// List all available Key Derivation Function (KDF) algorithms.
#[utoipa::path(
    responses(
        (status = 200, description = "List of available algorithms", body = inline(Vec<AlgorithmMetaDataItem>), content_type = "application/json",),
    ),
)]
#[get("/kdfs")]
pub async fn kdfs() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(
            &Tyst::instance()
                .kdfs()
                .get_algorithm_meta_datas()
                .into_iter()
                .map(AlgorithmMetaDataItem::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ))
}

/// Derive Key
///
/// Derive Key using Key Derivation Function (KDF).
#[utoipa::path(
    params(
        ("algorithm", description = "The KDF algorithm."),
    ),
    request_body = inline(KdfRequest),
    responses(
        (status = 200, description = "Success", body = inline(KdfResponse), content_type = "application/json",),
        (status = 404, description = "Bad request. Too many iterations or too large output requested."),
        (status = 404, description = "Fail"),
    ),
)]
#[post("/kdf/{algorithm}/derive")]
pub async fn derive(path: Path<String>, request: Json<KdfRequest>) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    // TODO: Make this a query param
    let params = KdfParams::default().set_psuedo_random_function(
        &tyst::encdec::oid::from_string("2.16.840.1.101.3.4.2.16").unwrap(),
    );
    if request.iterations > 16384 {
        return Ok(HttpResponse::build(StatusCode::BAD_REQUEST).finish());
    }
    if request.output_len > 65536 {
        return Ok(HttpResponse::build(StatusCode::BAD_REQUEST).finish());
    }
    if let Some(mut kdf) = Tyst::instance().kdfs().by_name_and_criteria_with_params(
        &algorithm_name,
        None,
        Some(params),
    ) {
        let mut response = KdfResponse {
            derived_key_b64: vec![0u8; usize::try_from(request.output_len).unwrap()],
        };
        kdf.derive(
            &request.password_b64,
            &request.salt_b64,
            usize::try_from(request.iterations).unwrap(),
            &mut response.derived_key_b64,
        );
        Ok(HttpResponse::build(StatusCode::OK)
            .body(serde_json::to_string_pretty(&response).unwrap()))
    } else {
        Err(ErrorBadRequest("Unable to find any matching KDF."))
    }
}
