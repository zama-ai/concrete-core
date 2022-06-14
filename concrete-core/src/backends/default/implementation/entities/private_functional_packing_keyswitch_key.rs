use crate::commons::crypto::glwe::PrivateFunctionalPackingKeyswitchKey as ImplPrivateFunctionalPackingKeyswitchKey;
use crate::prelude::markers::PrivateFunctionalPackingKeyswitchKeyKind;
use crate::prelude::PrivateFunctionalPackingKeyswitchKeyEntity;
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a private functional packing keyswitch key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateFunctionalPackingKeyswitchKey32(
    pub(crate) ImplPrivateFunctionalPackingKeyswitchKey<Vec<u32>>,
);
impl AbstractEntity for PrivateFunctionalPackingKeyswitchKey32 {
    type Kind = PrivateFunctionalPackingKeyswitchKeyKind;
}
impl PrivateFunctionalPackingKeyswitchKeyEntity for PrivateFunctionalPackingKeyswitchKey32 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> concrete_commons::parameters::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum PrivateFunctionalPackingKeyswitchKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a private functional packing keyswitch key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateFunctionalPackingKeyswitchKey64(
    pub ImplPrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
);
impl AbstractEntity for PrivateFunctionalPackingKeyswitchKey64 {
    type Kind = PrivateFunctionalPackingKeyswitchKeyKind;
}
impl PrivateFunctionalPackingKeyswitchKeyEntity for PrivateFunctionalPackingKeyswitchKey64 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> concrete_commons::parameters::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum PrivateFunctionalPackingKeyswitchKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
