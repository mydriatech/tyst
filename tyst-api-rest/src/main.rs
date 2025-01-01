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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod conf;
mod rest_api;

use conf::AppConfig;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tyst_api_rest_health::AppHealth;
use tyst_core::Tyst;

fn main() -> ExitCode {
    if let Err(e) = init_logger() {
        log::error!("Failed to initialize configuration: {e:?}");
        return ExitCode::FAILURE;
    }
    let app_config = Arc::new(AppConfig::new());
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(app_config.limits.available_parallelism())
        .build()
        .unwrap()
        .block_on(run_async(app_config))
}

/// Initialize the logging system and apply filters.
fn init_logger() -> Result<(), log::SetLoggerError> {
    env_logger::builder()
        // Set default log level
        .filter_level(log::LevelFilter::Debug)
        //.filter_level(log::LevelFilter::Trace)
        // Customize logging for dependencies
        .filter(Some("actix_http::h1"), log::LevelFilter::Debug)
        .filter(Some("mio::poll"), log::LevelFilter::Debug)
        .filter(Some("h2"), log::LevelFilter::Info)
        .filter(Some("actix_server"), log::LevelFilter::Warn)
        //.filter(Some("rustls::client"), log::LevelFilter::Info)
        //.filter(Some("rustls::common_state"), log::LevelFilter::Info)
        //.filter(Some("hyper_util::client"), log::LevelFilter::Info)
        //.write_style(env_logger::fmt::WriteStyle::Never)
        .write_style(env_logger::fmt::WriteStyle::Auto)
        .target(env_logger::fmt::Target::Stdout)
        .is_test(false)
        .parse_env(
            env_logger::Env::new()
                .filter("LOG_LEVEL")
                .write_style("LOG_STYLE"),
        )
        .try_init()
}

/// Async code entry point.
async fn run_async(app_config: Arc<AppConfig>) -> ExitCode {
    let app_future = run_async_abortable_with_logging(&app_config);
    let signals_future = block_until_signaled();
    tokio::select! {
        _ = app_future => {
            log::trace!("app_future finished");
        },
        _ = signals_future => {
            log::trace!("signals_future finished");
        },
    };
    ExitCode::SUCCESS
}

/// Block until SIGTERM or SIGINT is recieved.
async fn block_until_signaled() {
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = sigterm.recv() => {
            log::debug!("SIGTERM recieved.")
        },
        _ = sigint.recv() => {
            log::debug!("SIGINT recieved.")
        },
    };
}

/// Simple health check that gets the provider instance.
#[derive(Default)]
pub struct SimpleHealth {}

impl AppHealth for SimpleHealth {
    fn is_health_started(&self) -> bool {
        Tyst::instance();
        true
    }
    fn is_health_ready(&self) -> bool {
        self.is_health_started()
    }
    fn is_health_live(&self) -> bool {
        self.is_health_ready()
    }
}

async fn run_async_abortable_with_logging(app_config: &Arc<AppConfig>) {
    let app_health: Arc<dyn AppHealth> = Arc::new(SimpleHealth::default());
    rest_api::run_http_server(
        app_config.limits.available_parallelism(),
        &app_config.api.bind_address(),
        app_config.api.bind_port(),
        &app_health,
    )
    .await
    .unwrap();
}
