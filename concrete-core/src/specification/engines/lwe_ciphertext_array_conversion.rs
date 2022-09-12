use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayConversionError for LweCiphertextArrayConversionEngine @
}

/// A trait for engines converting LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a LWE ciphertext array containing
/// the conversion of the `input` LWE ciphertext array to a type with a different representation
/// (for instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweCiphertextArrayConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextArrayEntity,
    Output: LweCiphertextArrayEntity,
{
    /// Converts a LWE ciphertext array.
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &Input,
    ) -> Result<Output, LweCiphertextArrayConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn convert_lwe_ciphertext_array_unchecked(&mut self, input: &Input) -> Output;
}
