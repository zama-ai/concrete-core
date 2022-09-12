use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayFusingSubtractionError for LweCiphertextArrayFusingSubtractionEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output arrays length must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayFusingSubtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertextArray, OutputCiphertextArray>(
        output: &OutputCiphertextArray,
        input: &InputCiphertextArray,
    ) -> Result<(), Self>
    where
        InputCiphertextArray: LweCiphertextArrayEntity,
        OutputCiphertextArray: LweCiphertextArrayEntity,
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

/// A trait for engines subtracting (fusing) LWE ciphertexts arrays.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation subtracts the `input` LWE ciphertext array
/// to the `output` LWE ciphertext array.
///
/// # Formal Definition
pub trait LweCiphertextArrayFusingSubtractionEngine<InputCiphertextArray, OutputCiphertextArray>:
    AbstractEngine
where
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Subtracts two LWE ciphertext arrays.
    fn fuse_sub_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
    ) -> Result<(), LweCiphertextArrayFusingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts two LWE ciphertext arrays.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayFusingSubtractionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_sub_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
    );
}
