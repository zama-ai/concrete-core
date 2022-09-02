use super::engine_error;
use crate::prelude::AbstractEngine;

use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSeededCiphertextVectorEntity,
};

engine_error! {
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError
    for GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine @
}

/// A trait for engines transforming GLWE seeded ciphertexts vectors into GLWE ciphertexts vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing GLWE seeded ciphertext
/// vector into a GLWE ciphertext vector.
///
/// # Formal Definition
///
/// ## GLWE seeded ciphertext vector to GLWE ciphertext vector transformation
/// TODO
pub trait GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine<
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    InputCiphertextVector: GlweSeededCiphertextVectorEntity,
    OutputCiphertextVector: GlweCiphertextVectorEntity,
{
    /// Does the transformation of the GLWE seeded ciphertext vector into a GLWE ciphertext vector
    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        glwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> Result<
        OutputCiphertextVector,
        GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms a GLWE seeded ciphertext vector into a GLWE ciphertext vector
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> OutputCiphertextVector;
}
