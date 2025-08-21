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

//! Digest REST API resources

use super::rest_api_common::AlgorithmMetaDataItem;
use actix_web::Error;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Result;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::post;
use actix_web::web::Path;
use actix_web::web::Payload;
use tyst::Tyst;
use tyst::encdec::hex::ToHex;

/// List available digest algorithms
///
/// List all available messsage digest (hash) algorithms.
#[utoipa::path(
    responses(
        (status = 200, description = "List of available algorithms", body = inline(Vec<AlgorithmMetaDataItem>), content_type = "application/json",),
    ),
)]
#[get("/digests")]
pub async fn digests() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(
            &Tyst::instance()
                .digests()
                .get_algorithm_meta_datas()
                .into_iter()
                .map(AlgorithmMetaDataItem::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ))
}

/// Produce message digest (hash)
///
/// Produce message digest (hash) from binary input.
/// Sending "Accept: */*" returns the hex encoded version of the digest.
#[utoipa::path(
    request_body = inline(&[u8]),
    responses(
        (status = 200, description = "Message Digest (hash)", content(
            (Vec<u8> = "application/octet-stream"),
            (String = "plain/text", example="0123456789abcdef0123456789abcdef (hex encoded)"),
        )),
        (status = 400, description = "Failure"),
    ),
)]
#[post("/digest/{algorithm}")]
pub async fn digest(
    //app_state: Data<AppState>,
    path: Path<String>,
    payload: Payload,
    http_request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let algorithm_name = path.into_inner();
    let bytes = super::rest_api_common::get_bytes_from_request(
        payload,
        &http_request,
        super::rest_api_common::MAX_DOCUMENT_SIZE,
    )
    .await?;
    let http_headers = http_request.headers();
    let header_accept = http_headers
        .get("accept")
        .and_then(|header_value| header_value.to_str().ok())
        .unwrap_or("*/*");
    let digest = Tyst::instance()
        .digests()
        .by_name(&algorithm_name)
        .unwrap()
        .hash(&bytes);
    match header_accept {
        "*/*" => Ok(HttpResponse::build(StatusCode::OK).body(digest.to_hex())),
        "application/octet-stream" => Ok(HttpResponse::build(StatusCode::OK).body(digest)),
        bad_value => Ok(HttpResponse::build(StatusCode::BAD_REQUEST)
            .body(format!("Unsupported Accept header value '{bad_value}'."))),
    }
}
