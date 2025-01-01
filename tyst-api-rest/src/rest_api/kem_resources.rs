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

//! Key Encapsulation Mechanism (KEM) REST API resources

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
use actix_web::Error;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use actix_web::Result;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::sync::Arc;
use tyst_core::encdec::hex::ToHex;
use tyst_core::traits::common::BasicConfinement;
use tyst_core::traits::common::ConfinedObjectAsBytes;
use tyst_core::traits::common::Confinement;
use tyst_core::traits::common::ConfinementError;
use tyst_core::traits::common::GenericConfinement;
use tyst_core::traits::factory::FactoryCriteria;
use tyst_core::traits::kem::DecapsulationKey;
use tyst_core::traits::kem::EncapsulationKey;
use tyst_core::traits::kem::KemCipherText;
use tyst_core::traits::kem::KemParams;
use tyst_core::Tyst;
use utoipa::ToSchema;

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct KemKeyPairHolder {
    #[schema(inline)]
    pub decapsulation_key: ConfinedKeyMaterial,
    #[serde_as(as = "Base64")]
    pub encapsulation_key_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Deserialize)]
pub struct KemEncapsulationRequest {
    #[serde_as(as = "Base64")]
    pub encapsulation_key_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct KemEncapsulationResponse {
    #[serde_as(as = "Base64")]
    pub cipher_text_b64: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub shared_secret_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Deserialize)]
pub struct KemDecapsulationRequest {
    #[schema(inline)]
    pub decapsulation_key: ConfinedKeyMaterial,
    #[serde_as(as = "Base64")]
    pub cipher_text_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct KemDecapsulationResponse {
    #[serde_as(as = "Base64")]
    pub shared_secret_b64: Vec<u8>,
}

pub struct EncapsulationKeyHolder {
    pub key_material: Vec<u8>,
}
impl EncapsulationKey for EncapsulationKeyHolder {
    fn as_bytes(&self) -> Vec<u8> {
        self.key_material.clone()
    }
}
impl From<&[u8]> for EncapsulationKeyHolder {
    fn from(value: &[u8]) -> Self {
        Self {
            key_material: value.to_vec(),
        }
    }
}

pub struct DecapsulationKeyHolder {
    pub confinement: GenericConfinement,
    pub key_material: Option<Vec<u8>>,
}
impl DecapsulationKey for DecapsulationKeyHolder {
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(self.confinement.clone())
    }
}
impl ConfinedObjectAsBytes for DecapsulationKeyHolder {
    fn try_as_bytes(&self) -> std::result::Result<Vec<u8>, ConfinementError> {
        if let Some(value) = self.key_material.clone() {
            Ok(value)
        } else {
            Err(ConfinementError::new("Key material is not accessible."))
        }
    }
}

impl From<&ConfinedKeyMaterial> for DecapsulationKeyHolder {
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

/// List available KEM algorithms
///
/// List all available Key Encapsulation Mechanism (KEM) algorithms.
#[utoipa::path(
    responses(
        (status = 200, description = "List of available algorithms", body = inline(Vec<AlgorithmMetaDataItem>), content_type = "application/json",),
    ),
)]
#[get("/kems")]
pub async fn kems() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(
            &Tyst::instance()
                .kems()
                .get_algorithm_meta_datas()
                .into_iter()
                .map(AlgorithmMetaDataItem::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ))
}

/// Start generation of KEM en-/decapsulation keys.
///
/// Start generation of a pair of suitable encapsulation and decapsulation keys
/// for the Key Encapsulation Mechanism (KEM) algorithm.
#[utoipa::path(
    params(
        ("algorithm", description = "The KEM algorithm."),
    ),
    responses(
        (status = 303, description = "Key generation has started. Redirecting to result resource.",),
        (status = 404, description = "Failed to start"),
        (status = 429, description = "Too many requests are already in progress"),
    ),
)]
#[post("/kem/{algorithm}/keygen")]
pub async fn kem_keygen(
    app_state: Data<AppState>,
    path: Path<String>,
    http_request: HttpRequest,
) -> Result<impl Responder> {
    if app_state.kem_key_gen_requests.len() > 1024 {
        // TODO: This should take the time to clean out stale old ones and recheck
        return Ok(HttpResponse::build(StatusCode::TOO_MANY_REQUESTS).finish());
    }
    let algorithm_name = path.into_inner();
    let mut bytes = [0u8; 64];
    Tyst::instance().prng_fill_with_random(None, &mut bytes);
    let generation_request_id = bytes.as_slice().to_hex();
    let result_poll_url = http_request
        .url_for(
            "kem_keygen_result",
            [algorithm_name.to_owned(), generation_request_id.to_owned()],
        )
        .unwrap();
    app_state
        .kem_key_gen_requests
        .insert(generation_request_id.to_owned(), None);
    let kgr_clone = Arc::clone(&app_state.kem_key_gen_requests);
    tokio::task::spawn_blocking(move || {
        let (public_key, private_key) = Tyst::instance()
            .kems()
            .by_name(&algorithm_name)
            .unwrap()
            .key_gen();
        let confined_private_key = ConfinedKeyMaterial {
            confinement_type: Some(private_key.confinement().confinement_type().to_string()),
            object_reference: private_key.confinement().object_reference(),
            confinement_id: private_key.confinement().confinement_id(),
            key_material_b64: private_key.try_as_bytes().unwrap(),
        };
        kgr_clone.insert(
            generation_request_id,
            Some(KemKeyPairHolder {
                decapsulation_key: confined_private_key,
                encapsulation_key_b64: public_key.as_bytes(),
            }),
        );
    });
    // Post-Redirect-Get pattern since this might take a while
    Ok(HttpResponse::build(StatusCode::SEE_OTHER)
        .append_header(("Location", result_poll_url.as_str()))
        .finish())
}

/// Get generated KEM en-/decapsulation keys.
///
/// Get generated pair of suitable encapsulation and decapsulation keys for the
/// Key Encapsulation Mechanism (KEM) algorithm.
#[utoipa::path(
    params(
        ("algorithm", description = "The KEM algorithm."),
    ),
    responses(
        (status = 200, description = "Success", body = inline(KemKeyPairHolder), content_type = "application/json",),
        (status = 307, description = "Not ready yet"),
        (status = 404, description = "Key pair generation failed or was never started."),
    ),
)]
#[get("/kem/{algorithm}/keygen/{generation_request_id}")]
pub async fn kem_keygen_result(
    app_state: Data<AppState>,
    path: Path<(String, String)>,
    http_request: HttpRequest,
) -> Result<impl Responder> {
    let (algorithm_name, generation_request_id) = path.into_inner();
    if let Some(entry) = app_state.kem_key_gen_requests.get(&generation_request_id) {
        if let Some(kph) = entry.value() {
            app_state.se_key_gen_requests.remove(&generation_request_id);
            Ok(
                HttpResponse::build(StatusCode::OK)
                    .body(serde_json::to_string_pretty(kph).unwrap()),
            )
        } else {
            // Delay the requrest just a little
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            Ok(HttpResponse::build(StatusCode::TEMPORARY_REDIRECT)
                .append_header((
                    "location",
                    http_request
                        .url_for(
                            "kem_keygen_result",
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

/// Generate a shared secret and encapsulate it.
///
/// Generate a shared secret and encapsulate the shared secret using the KEM
/// encapsulation key. The encapsulated shared secret is returned both in plain
/// and as cipher_text. The cipher_text can be sent to the other party.
#[utoipa::path(
    request_body = inline(KemEncapsulationRequest),
    responses(
        (status = 200, description = "Success", body = inline(KemEncapsulationResponse), content_type = "application/json",),
        (status = 400, description = "Failure"),
    ),
)]
#[post("/kem/{algorithm}/encapsulate")]
pub async fn kem_encapsulate(
    path: Path<String>,
    request: Json<KemEncapsulationRequest>,
) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    let public_key: Box<dyn EncapsulationKey> = Box::new(EncapsulationKeyHolder::from(
        request.encapsulation_key_b64.as_slice(),
    ));
    if let Some((cipher_text, shared_secret)) = Tyst::instance()
        .kems()
        .by_name(&algorithm_name)
        .unwrap()
        .encapsulate(&public_key)
    {
        Ok(Json(KemEncapsulationResponse {
            cipher_text_b64: cipher_text.as_bytes(),
            shared_secret_b64: shared_secret.as_bytes(),
        }))
    } else {
        Err(ErrorBadRequest("Unable to complete the request."))
    }
}

/// Derive a shared secret though KEM decapsulation.
///
/// Derive the same shared secret as the other party by decapsulating the
/// recieved cipher text with the decapsulation key.
#[utoipa::path(
    request_body = inline(KemDecapsulationRequest),
    responses(
        (status = 200, description = "Success", body = inline(KemDecapsulationResponse), content_type = "application/json",),
        (status = 400, description = "Failure"),
    ),
)]
#[post("/kem/{algorithm}/decapsulate")]
pub async fn kem_decapsulate(
    path: Path<String>,
    request: Json<KemDecapsulationRequest>,
) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    let criteria = request
        .decapsulation_key
        .confinement_type
        .clone()
        .map(|confinement_type| {
            FactoryCriteria::default().require_confinement_type(confinement_type.as_str())
        });
    let params = KemParams::default();
    if let Some(mut kem) = Tyst::instance().kems().by_name_and_criteria_with_params(
        &algorithm_name,
        criteria,
        Some(params),
    ) {
        let private_key: Box<dyn DecapsulationKey> =
            Box::new(DecapsulationKeyHolder::from(&request.decapsulation_key));
        if let Some(shared_secret) = kem.decapsulate(
            &private_key,
            &KemCipherText::from(request.cipher_text_b64.clone()),
        ) {
            Ok(Json(KemDecapsulationResponse {
                shared_secret_b64: shared_secret.as_bytes(),
            }))
        } else {
            Err(ErrorBadRequest("Unable to complete the request."))
        }
    } else {
        Err(ErrorBadRequest("Unable to find any matching KEM."))
    }
}
