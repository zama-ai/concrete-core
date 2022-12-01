use crate::backends::cuda::private::crypto::plaintext::list::CudaPlaintextList;
use crate::prelude::PlaintextCount;
use crate::specification::entities::markers::PlaintextVectorKind;
use crate::specification::entities::{AbstractEntity, PlaintextVectorEntity};

/// A structure representing a vector of plaintexts with 32 bits of precision.
#[derive(Debug)]
pub struct CudaPlaintextVector32(pub(crate) CudaPlaintextList<u32>);
impl AbstractEntity for CudaPlaintextVector32 {
    type Kind = PlaintextVectorKind;
}
impl PlaintextVectorEntity for CudaPlaintextVector32 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.plaintext_count
    }
}

/// A structure representing a vector of plaintexts with 64 bits of precision.
#[derive(Debug)]
pub struct CudaPlaintextVector64(pub(crate) CudaPlaintextList<u64>);
impl AbstractEntity for CudaPlaintextVector64 {
    type Kind = PlaintextVectorKind;
}
impl PlaintextVectorEntity for CudaPlaintextVector64 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.plaintext_count
    }
}
