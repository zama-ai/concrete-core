use crate::backends::cuda::private::crypto::keyswitch::CudaLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::prelude::markers::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    GlweDimension, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, LweDimension,
};
use crate::specification::entities::AbstractEntity;

/// A structure representing a vector of private functional packing keyswitch keys used for a
/// circuit bootsrap with 32 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
    pub(crate) CudaLwePrivateFunctionalPackingKeyswitchKeyList<u32>,
);
impl AbstractEntity for CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity
    for CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32
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

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count
    }
}

/// A structure representing a vector of private functional packing keyswitch keys used for a
/// circuit bootstrap with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
    pub(crate) CudaLwePrivateFunctionalPackingKeyswitchKeyList<u64>,
);
impl AbstractEntity for CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity
    for CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64
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

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count
    }
}
