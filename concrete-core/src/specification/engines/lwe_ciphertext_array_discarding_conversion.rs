use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayDiscardingConversionError for LweCiphertextArrayDiscardingConversionEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: LweCiphertextArrayEntity,
        Output: LweCiphertextArrayEntity,
    {
        if input.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if input.lwe_ciphertext_count() != output.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines converting (discarding) LWE ciphertext arrays .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the conversion of the `input` LWE ciphertext array to a type with a different
/// representation (for instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweCiphertextArrayDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextArrayEntity,
    Output: LweCiphertextArrayEntity,
{
    /// Converts a LWE ciphertext array .
    fn discard_convert_lwe_ciphertext_array(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweCiphertextArrayDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE ciphertext array .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
