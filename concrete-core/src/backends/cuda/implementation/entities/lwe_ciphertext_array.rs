use std::fmt::Debug;

use crate::prelude::{LweCiphertextCount, LweDimension};

use crate::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::specification::entities::markers::LweCiphertextArrayKind;
use crate::specification::entities::{AbstractEntity, LweCiphertextArrayEntity};

/// A structure representing an array of LWE ciphertexts with 32 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextArray32(pub(crate) CudaLweList<u32>);

impl AbstractEntity for CudaLweCiphertextArray32 {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for CudaLweCiphertextArray32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }
}

/// A structure representing an array of LWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextArray64(pub(crate) CudaLweList<u64>);

impl AbstractEntity for CudaLweCiphertextArray64 {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for CudaLweCiphertextArray64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }
}
