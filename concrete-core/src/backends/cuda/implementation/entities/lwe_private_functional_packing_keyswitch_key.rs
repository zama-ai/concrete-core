use crate::backends::cuda::private::crypto::keyswitch::CudaLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::prelude::markers::LwePrivateFunctionalPackingKeyswitchKeyKind;
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
    LwePrivateFunctionalPackingKeyswitchKeyEntity,
};
use crate::specification::entities::AbstractEntity;
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a private functional packing keyswitch key with 32 bits of precision.
#[derive(Debug)]
pub struct CudaLwePrivateFunctionalPackingKeyswitchKey32(
    pub(crate) CudaLwePrivateFunctionalPackingKeyswitchKeyList<u32>,
);
impl AbstractEntity for CudaLwePrivateFunctionalPackingKeyswitchKey32 {
    type Kind = LwePrivateFunctionalPackingKeyswitchKeyKind;
}
impl LwePrivateFunctionalPackingKeyswitchKeyEntity
    for CudaLwePrivateFunctionalPackingKeyswitchKey32
{
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log
    }
}

/// A structure representing a private functional packing keyswitch key with 64 bits of precision.
#[derive(Debug)]
pub struct CudaLwePrivateFunctionalPackingKeyswitchKey64(
    pub(crate) CudaLwePrivateFunctionalPackingKeyswitchKeyList<u64>,
);
impl AbstractEntity for CudaLwePrivateFunctionalPackingKeyswitchKey64 {
    type Kind = LwePrivateFunctionalPackingKeyswitchKeyKind;
}
impl LwePrivateFunctionalPackingKeyswitchKeyEntity
    for CudaLwePrivateFunctionalPackingKeyswitchKey64
{
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension
    }

    fn output_polynomial_size(&self) -> crate::prelude::PolynomialSize {
        self.0.output_polynomial_size
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log
    }
}
