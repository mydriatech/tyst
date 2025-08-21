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

//! REST API server and resources.

mod digest_resources;
mod kem_resources;
mod mac_resources;
mod misc_resources;
mod prng_resources;
mod rest_api_common;
mod se_resources;

use self::kem_resources::KemKeyPairHolder;
use self::se_resources::SeKeyPairHolder;
use actix_web::http::header::ContentType;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;
use tyst_api_rest_health::AppHealth;
use tyst_api_rest_health::health_resources;
use utoipa::OpenApi;

/// Number of parallel requests the can be served for each assigned CPU core.
const WORKERS_PER_CORE: usize = 1024;

/// Shared state between requests.
#[derive(Clone)]
struct AppState {
    kem_key_gen_requests: Arc<SkipMap<String, Option<KemKeyPairHolder>>>,
    se_key_gen_requests: Arc<SkipMap<String, Option<SeKeyPairHolder>>>,
}

/// Run HTTP server.
pub async fn run_http_server(
    available_parallelism: usize,
    bind_address: &str,
    bind_port: u16,
    app_health: &Arc<dyn AppHealth>,
) -> std::io::Result<()> {
    let workers = available_parallelism;
    let max_connections = WORKERS_PER_CORE * workers;
    log::info!(
        "API described by http://{}:{}/openapi.json allows {max_connections} concurrent connections.",
        bind_address,
        bind_port,
    );
    let app_state: AppState = AppState {
        kem_key_gen_requests: Arc::new(SkipMap::default()),
        se_key_gen_requests: Arc::new(SkipMap::default()),
    };
    let app_data = web::Data::<AppState>::new(app_state);
    let app_health = web::Data::<Arc<dyn AppHealth>>::new(Arc::clone(app_health));

    HttpServer::new(move || {
        let scope = web::scope("/api/v1")
            .service(get_openapi)
            .service(digest_resources::digest)
            .service(digest_resources::digests)
            .service(misc_resources::pbkdf2_derive)
            .service(kem_resources::kems)
            .service(kem_resources::kem_keygen)
            .service(kem_resources::kem_keygen_result)
            .service(kem_resources::kem_encapsulate)
            .service(kem_resources::kem_decapsulate)
            .service(mac_resources::macs)
            .service(mac_resources::mac_keygen)
            .service(mac_resources::mac)
            .service(prng_resources::prngs)
            .service(prng_resources::prng_random)
            .service(se_resources::ses)
            .service(se_resources::se_keygen)
            .service(se_resources::se_keygen_result)
            .service(se_resources::se_sign)
            .service(se_resources::se_verify);
        App::new()
            .app_data(app_data.clone())
            .app_data(app_health.clone())
            .service(web::redirect("/openapi", "/api/v1/openapi.json"))
            .service(web::redirect("/openapi.json", "/api/v1/openapi.json"))
            .service(scope)
            .service(health_resources::health)
            .service(health_resources::health_live)
            .service(health_resources::health_ready)
            .service(health_resources::health_started)
    })
    .workers(workers)
    .backlog(u32::try_from(max_connections / 2).unwrap()) // Default is 2048
    .worker_max_blocking_threads(max_connections)
    .max_connections(max_connections)
    .bind_auto_h2c((bind_address, bind_port))?
    .disable_signals()
    .shutdown_timeout(5) // Default 30
    .run()
    .await
}

/// Serve Open API documentation.
#[get("/openapi.json")]
async fn get_openapi() -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(openapi_as_string())
}

/// Get the OpenAPI definition as a pretty JSON String.
pub fn openapi_as_string() -> String {
    #[derive(OpenApi)]
    #[openapi(
        // Use Cargo.toml as source for the "info" section
        paths(
            digest_resources::digest,
            digest_resources::digests,
            misc_resources::pbkdf2_derive,
            kem_resources::kems,
            kem_resources::kem_keygen,
            kem_resources::kem_keygen_result,
            kem_resources::kem_encapsulate,
            kem_resources::kem_decapsulate,
            mac_resources::macs,
            mac_resources::mac_keygen,
            mac_resources::mac,
            prng_resources::prngs,
            prng_resources::prng_random,
            se_resources::ses,
            se_resources::se_keygen,
            se_resources::se_keygen_result,
            se_resources::se_sign,
            se_resources::se_verify,
            health_resources::health,
            health_resources::health_live,
            health_resources::health_ready,
            health_resources::health_started,
        )
    )]
    struct ApiDoc;
    ApiDoc::openapi().to_pretty_json().unwrap()
}
