use super::engine_error;
use crate::prelude::AbstractEngine;

use crate::specification::entities::{LweCiphertextVectorEntity, LweSeededCiphertextVectorEntity};

engine_error! {
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngineError
    for LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine @
}

/// A trait for engines transforming LWE seeded ciphertext vectors into LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing LWE seeded ciphertext vector
/// into an LWE ciphertext vector.
///
/// # Formal Definition
///
/// ## LWE seeded ciphertext vector to LWE ciphertext vector transformation
/// cf [`here`](`crate::specification::engines::LweSeededToLweCiphertextTransformationEngine`)
pub trait LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine<
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    InputCiphertextVector: LweSeededCiphertextVectorEntity,
    OutputCiphertextVector:
        LweCiphertextVectorEntity<KeyDistribution = InputCiphertextVector::KeyDistribution>,
{
    /// Does the transformation of the LWE seeded ciphertext vector into an LWE ciphertext vector
    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        lwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> Result<
        OutputCiphertextVector,
        LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngineError<Self::EngineError>,
    >;

    /// Unsafely transforms an LWE seeded ciphertext vector into an LWE ciphertext vector
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngineError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> OutputCiphertextVector;
}
