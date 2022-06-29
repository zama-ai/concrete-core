use super::engine_error;
use crate::prelude::LweCiphertextVectorEntity;
use crate::specification::engines::AbstractEngine;

engine_error! {
    LweCiphertextVectorConsumingRetrievalError for LweCiphertextVectorConsumingRetrievalEngine @
}

pub trait LweCiphertextVectorConsumingRetrievalEngine<CiphertextVector, Container>:
    AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
{
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: CiphertextVector,
    ) -> Result<Container, LweCiphertextVectorConsumingRetrievalError<Self::EngineError>>;

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: CiphertextVector,
    ) -> Container;
}
