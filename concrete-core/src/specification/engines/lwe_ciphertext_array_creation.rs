use super::engine_error;
use crate::prelude::LweSize;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayCreationError for LweCiphertextArrayCreationEngine @
    EmptyContainer => "The container used to create the LWE ciphertext array is of length 0!"
}

impl<EngineError: std::error::Error> LweCiphertextArrayCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(container_length: usize) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptyContainer);
        }
        Ok(())
    }
}

/// A trait for engines creating an LWE ciphertext array from an arbitrary container.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates an LWE ciphertext array from the
/// abitrary `container`. By arbitrary here, we mean that `Container` can be any type that allows to
/// instantiate an `LweCiphertextArrayEntity`.
pub trait LweCiphertextArrayCreationEngine<Container, CiphertextArray>: AbstractEngine
where
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Creates an LWE ciphertext from an arbitrary container.
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: Container,
        lwe_size: LweSize,
    ) -> Result<CiphertextArray, LweCiphertextArrayCreationError<Self::EngineError>>;

    /// Unsafely creates an LWE ciphertext array from an arbitrary container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayCreationError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: Container,
        lwe_size: LweSize,
    ) -> CiphertextArray;
}
