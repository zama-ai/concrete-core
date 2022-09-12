use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextArrayEntity;

engine_error! {
    GlweCiphertextArrayConversionError for GlweCiphertextArrayConversionEngine @
}

/// A trait for engines converting GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext array containing
/// the conversion of the `input` GLWE ciphertext array to a type with a different representation
/// (for instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait GlweCiphertextArrayConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweCiphertextArrayEntity,
    Output: GlweCiphertextArrayEntity,
{
    /// Converts a GLWE ciphertext array.
    fn convert_glwe_ciphertext_array(
        &mut self,
        input: &Input,
    ) -> Result<Output, GlweCiphertextArrayConversionError<Self::EngineError>>;

    /// Unsafely converts a GLWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn convert_glwe_ciphertext_array_unchecked(&mut self, input: &Input) -> Output;
}
