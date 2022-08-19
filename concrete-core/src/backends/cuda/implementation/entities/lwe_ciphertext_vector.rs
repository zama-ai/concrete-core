use std::fmt::Debug;

use concrete_commons::parameters::{LweCiphertextCount, LweDimension};

use crate::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::specification::entities::markers::{BinaryKeyDistribution, LweCiphertextVectorKind};
use crate::specification::entities::{AbstractEntity, LweCiphertextVectorEntity};

/// A structure representing a vector of LWE ciphertexts with 32 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextVector32(pub(crate) CudaLweList<u32>);

impl AbstractEntity for CudaLweCiphertextVector32 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for CudaLweCiphertextVector32 {
    type KeyDistribution = BinaryKeyDistribution;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }
}

/// A structure representing a vector of LWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextVector64(pub(crate) CudaLweList<u64>);

impl AbstractEntity for CudaLweCiphertextVector64 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for CudaLweCiphertextVector64 {
    type KeyDistribution = BinaryKeyDistribution;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }
}
