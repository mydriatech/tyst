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

//! Psudedo Random Number Generator (PRNG) REST API resources

use super::rest_api_common::AlgorithmMetaDataItem;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::web::Path;
use actix_web::Error;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Result;
use tyst_core::encdec::hex::ToHex;
use tyst_core::Tyst;

/// List available PRNG algorithms
///
/// List all available Psudedo Random Number Generator (PRNG) algorithms.
#[utoipa::path(
    responses(
        (status = 200, description = "List of available algorithms", body = inline(Vec<AlgorithmMetaDataItem>), content_type = "application/json",),
    ),
)]
#[get("/prngs")]
pub async fn prngs() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(
            &Tyst::instance()
                .prngs()
                .get_algorithm_meta_datas()
                .into_iter()
                .map(AlgorithmMetaDataItem::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ))
}

/// Get random bytes.
///
/// Return random bytes of the requested length using and instance of the
/// requested Psudedo Random Number Generator (PRNG) algorithm.
/// If 'algorithm_name' is set to 'default', a cryptographically strong
/// generator will be choosen.
/// Sending 'Accept: */*' returns the hex encoded version of the digest.
#[utoipa::path(
    responses(
        (status = 200, description = "Random data", content_type = "application/octet-stream",),
        (status = 400, description = "Failure"),
    ),
)]
#[get("/prng/{algorithm}/random/{length}")]
pub async fn prng_random(
    path: Path<(String, usize)>,
    http_request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let (algorithm_name, length) = path.into_inner();
    if length > super::rest_api_common::MAX_DOCUMENT_SIZE {
        return Ok(HttpResponse::build(StatusCode::BAD_REQUEST).body(format!(
            "Max length is {}.",
            super::rest_api_common::MAX_DOCUMENT_SIZE
        )));
    }
    let mut target = vec![0u8; length];
    let algorithm_name = if algorithm_name.eq("default") {
        None
    } else {
        Some(algorithm_name.as_str())
    };
    Tyst::instance().prng_fill_with_random(algorithm_name, &mut target);
    let http_headers = http_request.headers();
    let header_accept = http_headers
        .get("accept")
        .and_then(|header_value| header_value.to_str().ok())
        .unwrap_or("*/*");
    match header_accept {
        "*/*" => Ok(HttpResponse::build(StatusCode::OK).body(target.to_hex())),
        "application/octet-stream" => Ok(HttpResponse::build(StatusCode::OK).body(target)),
        bad_value => Ok(HttpResponse::build(StatusCode::BAD_REQUEST)
            .body(format!("Unsupported Accept header value '{bad_value}'."))),
    }
}
