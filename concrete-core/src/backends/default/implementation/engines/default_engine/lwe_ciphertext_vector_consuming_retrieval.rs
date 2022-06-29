use crate::prelude::{
    DefaultEngine, LweCiphertextVector32, LweCiphertextVector64,
    LweCiphertextVectorConsumingRetrievalEngine, LweCiphertextVectorConsumingRetrievalError,
};

impl LweCiphertextVectorConsumingRetrievalEngine<LweCiphertextVector32, Vec<u32>>
    for DefaultEngine
{
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVector32,
    ) -> Result<Vec<u32>, LweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVector32,
    ) -> Vec<u32> {
        ciphertext.0.tensor.into_container()
    }
}

impl LweCiphertextVectorConsumingRetrievalEngine<LweCiphertextVector64, Vec<u64>>
    for DefaultEngine
{
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVector64,
    ) -> Result<Vec<u64>, LweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVector64,
    ) -> Vec<u64> {
        ciphertext.0.tensor.into_container()
    }
}
