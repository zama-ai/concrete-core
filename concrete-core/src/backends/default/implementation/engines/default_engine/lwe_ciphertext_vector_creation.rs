use crate::commons::crypto::lwe::LweList;
use crate::prelude::{
    DefaultEngine, LweCiphertextVector32, LweCiphertextVector64, LweCiphertextVectorCreationEngine,
    LweCiphertextVectorCreationError,
};
use concrete_commons::parameters::LweDimension;

impl LweCiphertextVectorCreationEngine<Vec<u32>, LweCiphertextVector32> for DefaultEngine {
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: Vec<u32>,
        lwe_dimension: LweDimension,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorCreationError<Self::EngineError>> {
        LweCiphertextVectorCreationError::perform_generic_checks(container.len(), lwe_dimension)?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_unchecked(container, lwe_dimension) })
    }

    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: Vec<u32>,
        lwe_dimension: LweDimension,
    ) -> LweCiphertextVector32 {
        LweCiphertextVector32(LweList::from_container(
            container,
            lwe_dimension.to_lwe_size(),
        ))
    }
}

impl LweCiphertextVectorCreationEngine<Vec<u64>, LweCiphertextVector64> for DefaultEngine {
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: Vec<u64>,
        lwe_dimension: LweDimension,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorCreationError<Self::EngineError>> {
        LweCiphertextVectorCreationError::perform_generic_checks(container.len(), lwe_dimension)?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_unchecked(container, lwe_dimension) })
    }

    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: Vec<u64>,
        lwe_dimension: LweDimension,
    ) -> LweCiphertextVector64 {
        LweCiphertextVector64(LweList::from_container(
            container,
            lwe_dimension.to_lwe_size(),
        ))
    }
}
