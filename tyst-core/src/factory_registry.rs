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

//! Generic registry implementation for cryptographic factories.

use crate::traits::factory::AlgorithmMetaData;
use crate::traits::factory::Factory;
use crate::traits::factory::FactoryCriteria;
use crate::traits::factory::FactoryRegistry;
use crossbeam_skiplist::SkipMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Generalized registry for crypto algorithm factories of a specific type.
pub struct FactoryRegistryImpl<F: ?Sized + 'static + Factory> {
    factory_registry: CommonFactoryRegistry<F>,
}

impl<F: ?Sized + 'static + Factory> Default for FactoryRegistryImpl<F> {
    fn default() -> Self {
        Self {
            factory_registry: CommonFactoryRegistry::default(),
        }
    }
}

impl<F: ?Sized + 'static + Factory> FactoryRegistry for FactoryRegistryImpl<F> {
    type Fact = F;

    fn register(&self, factory: Arc<Self::Fact>) {
        self.factory_registry.register(&factory);
    }

    fn get_algorithms(&self) -> Vec<String> {
        self.factory_registry.get_names()
    }

    fn get_algorithm_meta_datas(&self) -> Vec<AlgorithmMetaData> {
        self.factory_registry.get_algorithm_meta_datas()
    }

    fn by_oid_and_criteria_with_params(
        &self,
        oid: &str,
        criteria: Option<FactoryCriteria>,
        params: Option<<Self::Fact as Factory>::Parameters>,
    ) -> Option<Box<<Self::Fact as Factory>::Type>> {
        self.factory_registry
            .name_by_oid(oid)
            .and_then(|algorithm_name| {
                self.by_name_and_criteria_with_params(&algorithm_name, criteria, params)
            })
    }

    fn by_name_and_criteria_with_params(
        &self,
        algorithm_name: &str,
        criteria: Option<FactoryCriteria>,
        params: Option<<Self::Fact as Factory>::Parameters>,
    ) -> Option<Box<<Self::Fact as Factory>::Type>> {
        self.factory_registry
            .factory_by_name_and_criteria(algorithm_name, criteria)
            .map(|factory| {
                factory.new_by_name(
                    crate::Tyst::instance(),
                    algorithm_name,
                    params.unwrap_or_default(),
                )
            })
    }
}

#[doc(hidden)]
/// Actual common factory registry implementation
struct CommonFactoryRegistry<T: ?Sized + Factory> {
    provider_count: AtomicUsize,
    oid_to_name: SkipMap<String, String>,
    name_to_factory: SkipMap<String, SkipMap<usize, Arc<T>>>,
}

impl<T: ?Sized + Sync + Send + 'static + Factory> Default for CommonFactoryRegistry<T> {
    fn default() -> Self {
        Self {
            provider_count: AtomicUsize::default(),
            oid_to_name: SkipMap::default(),
            name_to_factory: SkipMap::default(),
        }
    }
}

impl<T: ?Sized + Sync + Send + 'static + Factory> CommonFactoryRegistry<T> {
    pub fn register(&self, factory: &Arc<T>) {
        let provider_count = self
            .provider_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for algorithm_meta_data in factory.get_algorithm_meta_datas() {
            let name = algorithm_meta_data.name().to_owned();
            if let Some(oid) = algorithm_meta_data.oid() {
                if let Some(entry) = self.oid_to_name.get(oid) {
                    if log::log_enabled!(log::Level::Debug) && !name.eq(entry.value()) {
                        log::debug!(
                            "Ignoring attempt to override registration OID {oid:?} from '{}' to '{name}'.",
                            entry.value(),
                        );
                    }
                } else {
                    self.oid_to_name.insert(oid.to_string(), name.to_owned());
                }
            }
            let factory_entries = self.name_to_factory.get_or_insert_with(name, SkipMap::new);
            factory_entries
                .value()
                .insert(provider_count, Arc::clone(factory));
        }
    }

    pub fn get_names(&self) -> Vec<String> {
        self.name_to_factory
            .iter()
            .map(|entry| entry.key().to_owned())
            .collect::<Vec<_>>()
    }

    pub fn get_algorithm_meta_datas(&self) -> Vec<AlgorithmMetaData> {
        let mut ret = Vec::new();
        for entry in self.name_to_factory.iter() {
            let name = entry.key();
            for entry in entry.value().iter() {
                let factory = Arc::clone(entry.value());
                let amd = factory.get_algorithm_meta_data(name).unwrap().clone();
                ret.push(amd);
            }
        }
        ret
    }

    pub fn name_by_oid(&self, oid: &str) -> Option<String> {
        self.oid_to_name
            .get(oid)
            .map(|algorithm_name_entry| algorithm_name_entry.value().to_owned())
    }

    pub fn factory_by_name_and_criteria(
        &self,
        algorithm_name: &str,
        criteria: Option<FactoryCriteria>,
    ) -> Option<Arc<T>> {
        self.name_to_factory
            .get(algorithm_name)
            .and_then(|factories_entry| {
                let factories = factories_entry.value();
                for factory_entry in factories {
                    let factory = factory_entry.value();
                    if !Self::fullfills_criteria(algorithm_name, factory, &criteria) {
                        continue;
                    }
                    return Some(Arc::clone(factory));
                }
                None::<Arc<T>>
            })
    }

    /// Check if factory meet search criteria
    fn fullfills_criteria(
        algorithm_name: &str,
        factory: &Arc<T>,
        criteria: &Option<FactoryCriteria>,
    ) -> bool {
        let mut ok = true;
        if let Some(criteria) = criteria {
            let algorithm_meta_data = factory.get_algorithm_meta_data(algorithm_name).unwrap();
            // If a specific provider requested?
            ok &= criteria
                .provider_id()
                .as_ref()
                .map(|required| required.eq(algorithm_meta_data.provider_id()))
                .unwrap_or(true);
            ok &= criteria
                .confinement_type()
                .as_ref()
                .map(|required| required.eq(algorithm_meta_data.confinement_type()))
                .unwrap_or(true);
        }
        ok
    }
}
