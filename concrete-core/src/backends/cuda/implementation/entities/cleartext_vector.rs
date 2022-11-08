use crate::backends::cuda::private::crypto::cleartext::list::CudaCleartextList;
use crate::prelude::CleartextCount;
use crate::specification::entities::markers::CleartextVectorKind;
use crate::specification::entities::{AbstractEntity, CleartextVectorEntity};

/// A structure representing a vector of cleartexts with 32 bits of precision.
#[derive(Debug)]
pub struct CudaCleartextVector32(pub(crate) CudaCleartextList<u32>);
impl AbstractEntity for CudaCleartextVector32 {
    type Kind = CleartextVectorKind;
}
impl CleartextVectorEntity for CudaCleartextVector32 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.cleartext_count
    }
}

/// A structure representing a vector of cleartexts with 64 bits of precision.
#[derive(Debug)]
pub struct CudaCleartextVector64(pub(crate) CudaCleartextList<u64>);
impl AbstractEntity for CudaCleartextVector64 {
    type Kind = CleartextVectorKind;
}
impl CleartextVectorEntity for CudaCleartextVector64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.cleartext_count
    }
}
