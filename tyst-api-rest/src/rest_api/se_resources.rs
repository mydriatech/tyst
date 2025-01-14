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

//! Signature engine REST API resources

use super::rest_api_common::AlgorithmMetaDataItem;
use super::rest_api_common::ConfinedKeyMaterial;
use super::AppState;
use actix_web::error::ErrorBadRequest;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::post;
use actix_web::web::Data;
use actix_web::web::Json;
use actix_web::web::Path;
use actix_web::web::Query;
use actix_web::Error;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use actix_web::Result;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::sync::Arc;
use tyst::encdec::hex::ToHex;
use tyst::traits::common::BasicConfinement;
use tyst::traits::common::ConfinedObjectAsBytes;
use tyst::traits::common::Confinement;
use tyst::traits::common::ConfinementError;
use tyst::traits::common::GenericConfinement;
use tyst::traits::factory::FactoryCriteria;
use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
use tyst::traits::se::SignatureEngineParams;
use tyst::Tyst;
use utoipa::schema;
use utoipa::ToSchema;

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct SeKeyPairHolder {
    #[schema(inline)]
    pub private_key: ConfinedKeyMaterial,
    #[serde_as(as = "Base64")]
    pub public_key_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Deserialize)]
pub struct SignatureVerificationRequest {
    #[serde_as(as = "Base64")]
    pub public_key_b64: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signature_b64: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub message_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Deserialize)]
pub struct SignatureGenerationRequest {
    #[schema(inline)]
    pub private_key: ConfinedKeyMaterial,
    #[serde_as(as = "Base64")]
    pub message_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct SignatureGenerationResponse {
    #[serde_as(as = "Base64")]
    pub signature_b64: Vec<u8>,
}

pub struct PrivateKeyHolder {
    pub confinement: GenericConfinement,
    pub key_material: Option<Vec<u8>>,
}
impl PrivateKey for PrivateKeyHolder {
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(self.confinement.clone())
    }
}

impl ConfinedObjectAsBytes for PrivateKeyHolder {
    fn try_as_bytes(&self) -> std::result::Result<Vec<u8>, ConfinementError> {
        if let Some(value) = self.key_material.clone() {
            Ok(value)
        } else {
            Err(ConfinementError::new("Key material is not accessible."))
        }
    }
}

impl From<&ConfinedKeyMaterial> for PrivateKeyHolder {
    fn from(value: &ConfinedKeyMaterial) -> Self {
        let confinement = if let Some(confinement_type) = value.confinement_type.clone() {
            GenericConfinement::new(
                confinement_type,
                value.confinement_id.clone(),
                value.object_reference.clone(),
            )
        } else {
            BasicConfinement::Soft.to_generic_confinement()
        };
        Self {
            confinement,
            key_material: Some(value.key_material_b64.clone()),
        }
    }
}

pub struct PublicKeyHolder {
    pub spki: Vec<u8>,
}
impl PublicKey for PublicKeyHolder {
    fn try_as_spki(&self) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.spki.clone())
    }
}

impl From<&[u8]> for PublicKeyHolder {
    fn from(value: &[u8]) -> Self {
        Self {
            spki: value.to_vec(),
        }
    }
}

/// List available signature engine algorithms
///
/// List all available asymmetric signature engine algorithms.
#[utoipa::path(
    responses(
        (status = 200, description = "List of available algorithms", body = inline(Vec<AlgorithmMetaDataItem>), content_type = "application/json",),
    ),
)]
#[get("/ses")]
pub async fn ses() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(
            &Tyst::instance()
                .ses()
                .get_algorithm_meta_datas()
                .into_iter()
                .map(AlgorithmMetaDataItem::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ))
}

#[derive(ToSchema, Deserialize)]
pub struct SignatureEngineParameters {
    pub strength: Option<u8>,
}

/// Start key pair generation.
///
/// Start generation of a suitable asymmetric key pair for the signature algorithm.
#[utoipa::path(
    params(
        ("algorithm", description = "The signature algorithm."),
        ("strength" = inline(SignatureEngineParameters), Query,),
    ),
    responses(
        (status = 303, description = "Key generation has started. Redirecting to result resource.",),
        (status = 404, description = "Failed to start"),
        (status = 429, description = "Too many requests are already in progress"),
    ),
)]
#[post("/se/{algorithm}/keygen")]
pub async fn se_keygen(
    app_state: Data<AppState>,
    path: Path<String>,
    query: Query<SignatureEngineParameters>,
    http_request: HttpRequest,
) -> Result<impl Responder> {
    if app_state.se_key_gen_requests.len() > 1024 {
        // TODO: This should take the time to clean out stale old ones and recheck
        return Ok(HttpResponse::build(StatusCode::TOO_MANY_REQUESTS).finish());
    }
    let algorithm_name = path.into_inner();
    let mut bytes = [0u8; 64];
    Tyst::instance().prng_fill_with_random(None, &mut bytes);
    let generation_request_id = bytes.as_slice().to_hex();
    let result_poll_url = http_request
        .url_for(
            "se_keygen_result",
            [algorithm_name.to_owned(), generation_request_id.to_owned()],
        )
        .unwrap();
    app_state
        .se_key_gen_requests
        .insert(generation_request_id.to_owned(), None);
    let kgr_clone = Arc::clone(&app_state.se_key_gen_requests);
    let params = query
        .strength
        .map(|strength| SignatureEngineParams::default().set_strength(usize::from(strength)));
    tokio::task::spawn_blocking(move || {
        let (public_key, private_key) = Tyst::instance()
            .ses()
            .by_name_and_criteria_with_params(&algorithm_name, None, params)
            .unwrap()
            .generate_key_pair();
        let confined_private_key = ConfinedKeyMaterial {
            confinement_type: Some(private_key.confinement().confinement_type().to_string()),
            object_reference: private_key.confinement().object_reference(),
            confinement_id: private_key.confinement().confinement_id(),
            key_material_b64: private_key.try_as_bytes().unwrap(),
        };
        kgr_clone.insert(
            generation_request_id,
            Some(SeKeyPairHolder {
                private_key: confined_private_key,
                public_key_b64: public_key.try_as_spki().unwrap(),
            }),
        );
    });
    // Post-Redirect-Get pattern since this might take a while
    Ok(HttpResponse::build(StatusCode::SEE_OTHER)
        .append_header(("Location", result_poll_url.as_str()))
        .finish())
}

/// Get generated key pair.
///
/// Get generated suitable asymmetric key pair for the signature algorithm.
#[utoipa::path(
    params(
        ("algorithm", description = "The signature algorithm."),
    ),
    responses(
        (status = 200, description = "Success", body = inline(SeKeyPairHolder), content_type = "application/json",),
        (status = 307, description = "Generation is still in progress."),
        (status = 404, description = "Key pair generation failed or was never started."),
    ),
)]
#[get("/se/{algorithm}/keygen/{generation_request_id}")]
pub async fn se_keygen_result(
    app_state: Data<AppState>,
    path: Path<(String, String)>,
    http_request: HttpRequest,
) -> Result<impl Responder> {
    let (algorithm_name, generation_request_id) = path.into_inner();
    if let Some(entry) = app_state.se_key_gen_requests.get(&generation_request_id) {
        if let Some(kph) = entry.value() {
            app_state.se_key_gen_requests.remove(&generation_request_id);
            Ok(
                HttpResponse::build(StatusCode::OK)
                    .body(serde_json::to_string_pretty(kph).unwrap()),
            )
        } else {
            // Delay the request just a little, so eager clients wont hammer the server
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            Ok(HttpResponse::build(StatusCode::TEMPORARY_REDIRECT)
                .append_header((
                    "location",
                    http_request
                        .url_for(
                            "se_keygen_result",
                            [algorithm_name.to_owned(), generation_request_id.to_owned()],
                        )
                        .unwrap()
                        .as_str(),
                ))
                .finish())
        }
    } else {
        Ok(HttpResponse::build(StatusCode::NOT_FOUND).finish())
    }
}

/// Generate a signature.
///
/// Generate a signature of the message (data) with the private key from the asymmetric key pair.
#[utoipa::path(
    request_body = inline(SignatureGenerationRequest),
    responses(
        (status = 200, description = "Success", body = inline(SignatureGenerationResponse), content_type = "application/json",),
        (status = 400, description = "Failure"),
    ),
)]
#[post("/se/{algorithm}/sign")]
pub async fn se_sign(
    path: Path<String>,
    request: Json<SignatureGenerationRequest>,
) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    let criteria = request
        .private_key
        .confinement_type
        .clone()
        .map(|confinement_type| {
            FactoryCriteria::default().require_confinement_type(confinement_type.as_str())
        });
    let params = SignatureEngineParams::default();
    if let Some(mut se) = Tyst::instance().ses().by_name_and_criteria_with_params(
        &algorithm_name,
        criteria,
        Some(params),
    ) {
        let private_key: Box<dyn PrivateKey> =
            Box::new(PrivateKeyHolder::from(&request.private_key));
        if let Some(signature_b64) = se.sign(&private_key, &request.message_b64) {
            Ok(Json(SignatureGenerationResponse { signature_b64 }))
        } else {
            Err(ErrorBadRequest("Unable to complete the request."))
        }
    } else {
        Err(ErrorBadRequest(
            "Unable to find any matching signature engine.",
        ))
    }
}

/// Verify a signature.
///
/// Verify a signature of the message (data) with the public key from the asymmetric key pair.
#[utoipa::path(
    request_body = inline(SignatureVerificationRequest),
    responses(
        (status = 204, description = "Success"),
        (status = 400, description = "Signature verification failed"),
    ),
)]
#[post("/se/{algorithm}/verify")]
pub async fn se_verify(
    //app_state: Data<AppState>,
    path: Path<String>,
    request: Json<SignatureVerificationRequest>,
    //http_request: HttpRequest,
) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    let public_key: Box<dyn PublicKey> =
        Box::new(PublicKeyHolder::from(request.public_key_b64.as_slice()));
    //let public_key: Box<dyn PublicKey> = Box::new(request.public_key.clone());
    if Tyst::instance()
        .ses()
        .by_name(&algorithm_name)
        .unwrap()
        .verify(&public_key, &request.signature_b64, &request.message_b64)
    {
        Ok(HttpResponse::build(StatusCode::NO_CONTENT).finish())
    } else {
        Err(ErrorBadRequest("Signature verification failed."))
    }
}
