use crate::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey as ImplFunctionalPackingKeyswitchKey;
use crate::prelude::markers::FunctionalPackingKeyswitchKeyKind;
use crate::prelude::FunctionalPackingKeyswitchKeyEntity;
use crate::specification::entities::markers::BinaryKeyDistribution;
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
};
#[cfg(feature = "serde_serialize")]
use serde::{Deserialize, Serialize};

/// A structure representing a functional packing keyswitch key with 32 bits of precision.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionalPackingKeyswitchKey32(pub(crate) ImplFunctionalPackingKeyswitchKey<Vec<u32>>);
impl AbstractEntity for FunctionalPackingKeyswitchKey32 {
    type Kind = FunctionalPackingKeyswitchKeyKind;
}
impl FunctionalPackingKeyswitchKeyEntity for FunctionalPackingKeyswitchKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;

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

/// A structure representing a functional packing keyswitch key with 64 bits of precision.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionalPackingKeyswitchKey64(pub ImplFunctionalPackingKeyswitchKey<Vec<u64>>);
impl AbstractEntity for FunctionalPackingKeyswitchKey64 {
    type Kind = FunctionalPackingKeyswitchKeyKind;
}
impl FunctionalPackingKeyswitchKeyEntity for FunctionalPackingKeyswitchKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;

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
