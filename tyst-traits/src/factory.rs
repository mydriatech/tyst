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

//! Factory and FactoryRegistry traits

use std::sync::Arc;

use crate::common::BasicConfinement;
use crate::common::Confinement;

/// Criteria for filtering available algorithms or selecting a specific
/// implementation
#[derive(Default)]
pub struct FactoryCriteria {
    provider_id: Option<String>,
    confinement_type: Option<String>,
}

impl FactoryCriteria {
    #[doc(hidden)]
    pub fn provider_id(&self) -> &Option<String> {
        &self.provider_id
    }

    /// Require that the implementation comes from a specific provider.
    pub fn require_provider_id(mut self, provider_id: &str) -> Self {
        self.provider_id = Some(provider_id.to_owned());
        self
    }

    #[doc(hidden)]
    pub fn confinement_type(&self) -> &Option<String> {
        &self.confinement_type
    }

    /// Require that the implementation comes from a specific provider.
    pub fn require_confinement_type(mut self, confinement_type: &str) -> Self {
        self.confinement_type = Some(confinement_type.to_owned());
        self
    }
}

/// Registry for `Factory` implementations
pub trait FactoryRegistry {
    /// Type of Factory implementation
    type Fact: ?Sized + 'static + Factory;

    /// Add implementation to this registry
    fn register(&self, factory: Arc<Self::Fact>);

    /// Get names (human readable identifiers) of registered algorithms
    fn get_algorithms(&self) -> Vec<String>;

    /// Get names and meta data of registered algorithms
    fn get_algorithm_meta_datas(&self) -> Vec<AlgorithmMetaData>;

    /// Retrieve any  `Factory` instance by Object Identifier (OID) using default
    /// parameters if such OID is available for the algorithm.
    fn by_oid(&self, oid: &str) -> Option<Box<<Self::Fact as Factory>::Type>> {
        self.by_oid_and_criteria_with_params(oid, None, None)
    }

    /// Retrieve a `Factory` instance by Object Identifier (OID) and
    /// [FactoryCriteria] using default parameters if such OID is available for
    /// the algorithm.
    fn by_oid_and_criteria_with_params(
        &self,
        oid: &str,
        criteria: Option<FactoryCriteria>,
        params: Option<<Self::Fact as Factory>::Parameters>,
    ) -> Option<Box<<Self::Fact as Factory>::Type>>;

    /// Retrieve any `Factory` instance by name using default parameters.
    fn by_name(&self, algorithm_name: &str) -> Option<Box<<Self::Fact as Factory>::Type>> {
        self.by_name_and_criteria_with_params(algorithm_name, None, None)
    }

    /// Retrieve a `Factory` instance by name and [FactoryCriteria].
    fn by_name_and_criteria_with_params(
        &self,
        algorithm_name: &str,
        criteria: Option<FactoryCriteria>,
        params: Option<<Self::Fact as Factory>::Parameters>,
    ) -> Option<Box<<Self::Fact as Factory>::Type>>;
}

/// Generic factory for crypto algorithm implementations
pub trait Factory: Sync + Send {
    /// Type of algorithm implementation
    type Type: ?Sized;
    /// Type of parameters matching the algorithm implementation
    type Parameters: Default;

    /// Return a new instance of a crypto algorithm implementation
    fn new_by_name(
        &self,
        registry: Box<&'static dyn crate::CryptoRegistry>,
        algorithm_name: &str,
        params: Self::Parameters,
    ) -> Box<Self::Type>;

    /// Return name and additional [meta data](AlgorithmMetaData) for algorithms implemented by
    /// this factory.
    fn get_algorithm_meta_datas(&self) -> &[AlgorithmMetaData];

    /// Return name and additional meta data for an algorithm implemented by
    /// this factory.
    fn get_algorithm_meta_data(&self, name: &str) -> Option<&AlgorithmMetaData> {
        self.get_algorithm_meta_datas()
            .iter()
            .find(|amd| amd.name().eq(name))
    }
}

/**Holds name, provider identifier and additional available meta-data for
an crypto algorithm implementation.

### Example

```
# use tyst_traits::factory::AlgorithmMetaData;
AlgorithmMetaData::new("Impl-TLA-1024", "my_custom_provider_id")
    .set_oid("1.2.3.4.5.6.7.8.9.0")
    .set_confinement_type("my_hsm_impl");
```
*/
#[derive(Clone)]
pub struct AlgorithmMetaData {
    name: String,
    provider_id: String,
    confinement_type: String,
    oid: Option<String>,
}

impl AlgorithmMetaData {
    /// Create a new instance with mandatory fields.
    pub fn new(name: &str, provider_id: &str) -> Self {
        Self {
            name: name.to_string(),
            provider_id: provider_id.to_string(),
            confinement_type: BasicConfinement::Soft.confinement_type().to_string(),
            oid: None,
        }
    }

    /// Human readable identifier of the crypto algorithm implementation.
    #[doc(hidden)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Identifier of the implementation/driver.
    #[doc(hidden)]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Get the confinement type this implementation supports.
    #[doc(hidden)]
    pub fn confinement_type(&self) -> &str {
        &self.confinement_type
    }

    /// Set the confinement type this implementation supports.
    pub fn set_confinement_type(mut self, confinement_type: &str) -> Self {
        self.confinement_type = confinement_type.to_owned();
        self
    }

    /// (Optional) Object Identifier (OID) of the crypto algorithm implementation.
    #[doc(hidden)]
    pub fn oid(&self) -> Option<&str> {
        self.oid.as_deref()
    }

    /// (Optional) Builder style setter for the OID of the implementation.
    pub fn set_oid(mut self, oid: &str) -> Self {
        self.oid = Some(oid.to_owned());
        self
    }
}
