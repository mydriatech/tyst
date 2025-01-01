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

//! Message Authentication Code (MAC) REST API resources

use super::rest_api_common::AlgorithmMetaDataItem;
use super::rest_api_common::ConfinedKeyMaterial;
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
use tyst_core::traits::common::BasicConfinement;
use tyst_core::traits::common::ConfinedObjectAsBytes;
use tyst_core::traits::common::Confinement;
use tyst_core::traits::common::ConfinementError;
use tyst_core::traits::common::GenericConfinement;
use tyst_core::traits::factory::FactoryCriteria;
use tyst_core::traits::mac::MacKey;
use tyst_core::traits::mac::MacParams;
use tyst_core::Tyst;
use utoipa::ToSchema;

#[serde_as]
#[derive(ToSchema, Deserialize)]
pub struct MacRequest {
    #[schema(inline)]
    pub key: ConfinedKeyMaterial,
    #[serde_as(as = "Base64")]
    pub message_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct MacResponse {
    #[serde_as(as = "Base64")]
    pub mac_b64: Vec<u8>,
}

#[serde_as]
#[derive(ToSchema, Serialize)]
pub struct MacKeyGenerationResponse {
    #[schema(inline)]
    pub key: ConfinedKeyMaterial,
}

pub struct MacKeyHolder {
    pub confinement: GenericConfinement,
    pub key_material: Option<Vec<u8>>,
}
impl MacKey for MacKeyHolder {
    fn confinement(&self) -> Box<dyn Confinement> {
        Box::new(self.confinement.clone())
    }
}
impl ConfinedObjectAsBytes for MacKeyHolder {
    fn try_as_bytes(&self) -> std::result::Result<Vec<u8>, ConfinementError> {
        if let Some(value) = self.key_material.clone() {
            Ok(value)
        } else {
            Err(ConfinementError::new("Key material is not accessible."))
        }
    }
}

impl From<&ConfinedKeyMaterial> for MacKeyHolder {
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

/// List available MAC algorithms
///
/// List all available Message Authentication Code (MAC) algorithms.
#[utoipa::path(
    responses(
        (status = 200, description = "List of available algorithms", body = inline(Vec<AlgorithmMetaDataItem>), content_type = "application/json",),
    ),
)]
#[get("/macs")]
pub async fn macs() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(
            &Tyst::instance()
                .macs()
                .get_algorithm_meta_datas()
                .into_iter()
                .map(AlgorithmMetaDataItem::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ))
}

/// Generation of MAC key.
///
/// Generate a suitable key for the Message Authentication Code (MAC) algorithm.
#[utoipa::path(
    params(
        ("algorithm", description = "The MAC algorithm."),
    ),
    responses(
        (status = 200, description = "Success", body = inline(MacKeyGenerationResponse), content_type = "application/json",),
        (status = 404, description = "Key generation failed or was never started."),
    ),
)]
#[post("/mac/{algorithm}/keygen")]
pub async fn mac_keygen(
    //app_state: Data<AppState>,
    path: Path<String>,
    //http_request: HttpRequest,
) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    let key = Tyst::instance()
        .macs()
        .by_name(&algorithm_name)
        .unwrap()
        .generate_key();
    let confined_private_key = ConfinedKeyMaterial {
        confinement_type: Some(key.confinement().confinement_type().to_string()),
        object_reference: key.confinement().object_reference(),
        confinement_id: key.confinement().confinement_id(),
        key_material_b64: key.try_as_bytes().unwrap(),
    };
    Ok(HttpResponse::build(StatusCode::OK).body(
        serde_json::to_string_pretty(&MacKeyGenerationResponse {
            key: confined_private_key,
        })
        .unwrap(),
    ))
}

/// Produce MAC
///
/// Produce Message Authentication Code (MAC).
#[utoipa::path(
    params(
        ("algorithm", description = "The MAC algorithm."),
    ),
    request_body = inline(MacRequest),
    responses(
        (status = 200, description = "Success", body = inline(MacResponse), content_type = "application/json",),
        (status = 404, description = "Fail"),
    ),
)]
#[post("/mac/{algorithm}/mac")]
pub async fn mac(path: Path<String>, request: Json<MacRequest>) -> Result<impl Responder> {
    let algorithm_name = path.into_inner();
    let criteria = request
        .key
        .confinement_type
        .clone()
        .map(|confinement_type| {
            FactoryCriteria::default().require_confinement_type(confinement_type.as_str())
        });
    let params = MacParams::default();
    if let Some(mut mac) = Tyst::instance().macs().by_name_and_criteria_with_params(
        &algorithm_name,
        criteria,
        Some(params),
    ) {
        let key: Box<dyn MacKey> = Box::new(MacKeyHolder::from(&request.key));
        Ok(Json(MacResponse {
            mac_b64: mac.mac(&key, &request.message_b64),
        }))
    } else {
        Err(ErrorBadRequest("Unable to find any matching MAC."))
    }
}
