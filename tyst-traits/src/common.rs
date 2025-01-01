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

//! Common traits, errors etc.

/// Information about where the object can be used.
pub trait Confinement: Sync + Send {
    /// Type of confinement.
    fn confinement_type(&self) -> &str;
    /// Identifier used by provider to locate the correct confinement.
    fn confinement_id(&self) -> Option<String>;
    /// Identifier used by provider to locate the correct object.
    fn object_reference(&self) -> Option<String>;
}

/// Information about where the object can be used.
pub trait ConfinedObjectAsBytes {
    /// Return the object in plain text as raw bytes.
    ///
    /// The implementation is responsible for any kind of fetching and
    /// unwrapping that is needed.
    fn try_as_bytes(&self) -> Result<Vec<u8>, ConfinementError>;
}

#[derive(Clone)]
/// Basic confinement
pub enum BasicConfinement {
    /// Soft plain text storage in memory
    Soft,
    // Stored in a Hardware Security Module cluster identified by `storage_id`
    //HsmStored { hsm_security_world_id, key_id }
    // Unwrappable in a Hardware Security Module cluster identified by `storage_id`
    //HsmWrapped { hsm_security_world_id, key_id  }
}
impl Confinement for BasicConfinement {
    fn confinement_type(&self) -> &str {
        match self {
            Self::Soft => "soft",
        }
    }
    fn confinement_id(&self) -> Option<String> {
        match self {
            Self::Soft => None,
        }
    }
    fn object_reference(&self) -> Option<String> {
        match self {
            Self::Soft => None,
        }
    }
}
impl BasicConfinement {
    /// Convert [BasicConfinement] to [GenericConfinement].
    pub fn to_generic_confinement(&self) -> GenericConfinement {
        GenericConfinement {
            confinement_type: self.confinement_type().to_string(),
            confinement_id: self.confinement_id(),
            object_reference: self.object_reference(),
        }
    }
}

#[derive(Clone)]
/// Generic [Confinement] implementation.
pub struct GenericConfinement {
    /// Type of confinement.
    confinement_type: String,
    /// Identifier used by provider to locate the correct confinement.
    confinement_id: Option<String>,
    /// Identifier used by provider to locate the correct object.
    object_reference: Option<String>,
}
impl GenericConfinement {
    /// Return a new instance.
    pub fn new(
        confinement_type: String,
        confinement_id: Option<String>,
        object_reference: Option<String>,
    ) -> Self {
        Self {
            confinement_type,
            confinement_id,
            object_reference,
        }
    }
}
impl Confinement for GenericConfinement {
    fn confinement_type(&self) -> &str {
        self.confinement_type.as_str()
    }
    fn confinement_id(&self) -> Option<String> {
        self.confinement_id.clone()
    }
    fn object_reference(&self) -> Option<String> {
        self.object_reference.clone()
    }
}

#[derive(Debug)]
/// Error indicating a problem retrieving the objects byte encoded form.
pub struct ConfinementError {
    msg: String,
}

impl ConfinementError {
    /// Return a new instance.
    pub fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl std::fmt::Display for ConfinementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for ConfinementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
    fn description(&self) -> &str {
        &self.msg
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}
