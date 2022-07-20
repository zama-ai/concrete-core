use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;
use concrete_commons::parameters::LweSize;

engine_error! {
    LweCiphertextVectorCreationError for LweCiphertextVectorCreationEngine @
    EmptyContainer => "The container used to create the LWE ciphertext vector is of length 0!"
}

impl<EngineError: std::error::Error> LweCiphertextVectorCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(container_length: usize) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptyContainer);
        }
        Ok(())
    }
}

/// A trait for engines creating an LWE ciphertext vector from an arbitrary container.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates an LWE ciphertext vector from the
/// abitrary `container`. By arbitrary here, we mean that `Container` can be any type that allows to
/// instantiate an `LweCiphertextVectorEntity`.
pub trait LweCiphertextVectorCreationEngine<Container, Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextVectorEntity,
{
    /// Creates an LWE ciphertext from an arbitrary container.
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: Container,
        lwe_size: LweSize,
    ) -> Result<Ciphertext, LweCiphertextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates an LWE ciphertext vector from an arbitrary container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorCreationError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: Container,
        lwe_size: LweSize,
    ) -> Ciphertext;
}
