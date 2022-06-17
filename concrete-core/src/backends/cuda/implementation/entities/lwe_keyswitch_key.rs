use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};

use crate::backends::cuda::private::crypto::keyswitch::CudaLweKeyswitchKey;
use crate::specification::entities::markers::{BinaryKeyDistribution, LweKeyswitchKeyKind};
use crate::specification::entities::{AbstractEntity, LweKeyswitchKeyEntity};

/// A structure representing a keyswitch key for 32 bits precision ciphertexts on the GPU.
#[derive(Debug, Clone, PartialEq)]
pub struct CudaLweKeyswitchKey32(pub(crate) CudaLweKeyswitchKey<u32>);

impl AbstractEntity for CudaLweKeyswitchKey32 {
    type Kind = LweKeyswitchKeyKind;
}

impl LweKeyswitchKeyEntity for CudaLweKeyswitchKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.output_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

/// A structure representing a  keyswitch key for 64 bits precision ciphertexts on the GPU.
#[derive(Debug, Clone, PartialEq)]
pub struct CudaLweKeyswitchKey64(pub(crate) CudaLweKeyswitchKey<u64>);

impl AbstractEntity for CudaLweKeyswitchKey64 {
    type Kind = LweKeyswitchKeyKind;
}

impl LweKeyswitchKeyEntity for CudaLweKeyswitchKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.output_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}
