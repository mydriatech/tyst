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

//! Helper for downloading test vectors and caching them on disk.

use std::time::Duration;
use ureq::{Agent, AgentBuilder};
use url::Url;

/// Download of test resources that are not present on disk
pub struct CachedUrlResource {
    agent: Agent,
    relative_cache_dir_names: Vec<String>,
}

impl CachedUrlResource {
    /// Cache downloads relative to `${CARGO_MANIFEST_DIR}`
    pub fn with_resource_dir(relative_cache_dir_names: &[&str]) -> Self {
        Self {
            agent: AgentBuilder::new()
                .timeout_read(Duration::from_secs(5))
                .timeout_write(Duration::from_secs(5))
                .redirects(5)
                .build(),
            relative_cache_dir_names: relative_cache_dir_names
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        }
    }

    pub fn fetch(&self, url: &str) -> Option<String> {
        self.from_cache(url)
            .or_else(|| self.persist(url, self.download(url)))
    }

    fn download(&self, url: &str) -> Option<String> {
        log::info!("Downloading '{url}'.");
        self.agent
            .get(url)
            .call()
            .map_err(|e| {
                log::info!("Failed request to {url}: {e:?}");
            })
            .ok()
            .and_then(|response| {
                response
                    .into_string()
                    .map_err(|e| {
                        log::info!("Failed to parse response from {url}: {e:?}");
                    })
                    .ok()
            })
    }

    fn from_cache(&self, url: &str) -> Option<String> {
        if let Some(filename) = self.url_to_filename(url) {
            let ret = std::fs::read_to_string(filename.clone())
                .map_err(|e| {
                    log::error!("Failed to parse file '{filename}': {e:?}");
                })
                .ok();
            if log::log_enabled!(log::Level::Debug) && ret.is_some() {
                log::debug!("Found local cached file '{url}'. (Version of this file is ignored.)");
            }
            return ret;
        }
        None
    }

    fn persist(&self, url: &str, contents: Option<String>) -> Option<String> {
        if let Some(filename) = self.url_to_filename(url) {
            if let Some(contents) = &contents {
                std::fs::write(&filename, contents)
                    .map_err(|e| {
                        log::error!("Failed to write file '{filename}': {e:?}");
                    })
                    .ok();
            }
        }
        contents
    }

    fn url_to_filename(&self, url: &str) -> Option<String> {
        let u = Url::parse(url).unwrap();
        if let Some(mut x) = u.path_segments().map(|v| v.rev()) {
            if let Some(filename) = x.next() {
                if let Some(dirname) = x.next() {
                    let mut filename_full = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                    for dir_name in &self.relative_cache_dir_names {
                        filename_full.push(dir_name);
                    }
                    filename_full.push(format!("{dirname}-{filename}"));
                    return filename_full.to_str().map(String::from);
                }
            }
        }
        None
    }
}
