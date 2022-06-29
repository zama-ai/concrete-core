use super::engine_error;
use crate::prelude::LweCiphertextVectorEntity;
use crate::specification::engines::AbstractEngine;
use concrete_commons::parameters::LweDimension;

engine_error! {
    LweCiphertextVectorCreationError for LweCiphertextVectorCreationEngine @
    EmptyContainer => "The container used to create the LWE ciphertext is of length 0!",
    InvalidContainerSize => "The size of the container is not a multiple of the lwe size !"
}

impl<EngineError: std::error::Error> LweCiphertextVectorCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(
        container_length: usize,
        dimension: LweDimension,
    ) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptyContainer);
        } else if container_length % (dimension.0 + 1) != 0 {
            return Err(Self::InvalidContainerSize);
        }
        Ok(())
    }
}

pub trait LweCiphertextVectorCreationEngine<Container, CiphertextVector>: AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
{
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: Container,
        lwe_dimension: LweDimension,
    ) -> Result<CiphertextVector, LweCiphertextVectorCreationError<Self::EngineError>>;

    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: Container,
        lwe_dimension: LweDimension,
    ) -> CiphertextVector;
}
