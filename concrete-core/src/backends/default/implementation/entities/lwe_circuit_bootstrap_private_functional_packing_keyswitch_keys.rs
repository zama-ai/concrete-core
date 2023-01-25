use crate::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList as ImplLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::prelude::markers::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    GlweDimension, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, LweDimension,
};
use crate::specification::entities::AbstractEntity;
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of private functional packing keyswitch keys used for a
/// circuit bootsrap with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
    pub(crate) ImplLwePrivateFunctionalPackingKeyswitchKeyList<Vec<u32>>,
);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity
    for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32
{
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of private functional packing keyswitch keys used for a
/// circuit bootsrap with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
    pub ImplLwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity
    for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64
{
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32<'a>(pub(crate) ImplLwePrivateFunctionalPackingKeyswitchKeyList<&'a [u32]>);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32<'_> {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'a>(pub(crate) ImplLwePrivateFunctionalPackingKeyswitchKeyList<&'a mut [u32]>);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'_> {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64<'a>(pub(crate) ImplLwePrivateFunctionalPackingKeyswitchKeyList<&'a [u64]>);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64<'_> {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'a>(pub(crate) ImplLwePrivateFunctionalPackingKeyswitchKeyList<&'a mut [u64]>);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'_> {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}
