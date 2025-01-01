# TYST REST API Health library

[Eclipse MicroProfile Health 3.1](https://github.com/eclipse/microprofile-health/blob/main/spec/src/main/asciidoc/protocol-wireformat.asciidoc) implementation for the Rust web framework
[Actix Web](https://actix.rs/).

## Endpoints

* `/health`: Combined status of initialized, readiness and liveness.
* `/health/started`: Status of app initialization.
* `/health/ready`: App's readiness to serve requests.
* `/health/live`: Status of app's operations.

## Usage

```text
use test_api_rest_health::AppHealth;
use test_api_rest_health::health_resources;

#[derive(Default)]
pub struct DummyHealth {}
impl AppHealth for DummyHealth {
    // Implement real health condition checks here
}

    ...
    let app_health = web::Data::<Arc<dyn AppHealth>>::new(
        Arc::new(DummyHealth::default())
    );
    ...
    HttpServer::new(move || {
        ...
        App::new()
            .app_data(app_health.clone())
            .service(health_resources::health)
            .service(health_resources::health_live)
            .service(health_resources::health_ready)
            .service(health_resources::health_started)
    })
    .run()
    .await
```
