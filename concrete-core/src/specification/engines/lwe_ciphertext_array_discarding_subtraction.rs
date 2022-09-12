use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayDiscardingSubtractionError for LweCiphertextArrayDiscardingSubtractionEngine @
    LweDimensionMismatch => "The input and output LWE dimensions must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingSubtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<OutputCiphertextArray, InputCiphertextArray>(
        output: &OutputCiphertextArray,
        input_1: &InputCiphertextArray,
        input_2: &InputCiphertextArray,
    ) -> Result<(), Self>
    where
        InputCiphertextArray: LweCiphertextArrayEntity,
        OutputCiphertextArray: LweCiphertextArrayEntity,
    {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(Self::LweDimensionMismatch);
        }
        if output.lwe_ciphertext_count() != input_1.lwe_ciphertext_count()
            || output.lwe_ciphertext_count() != input_2.lwe_ciphertext_count()
        {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines subtracting (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the element-wise subtraction of the `input_2` LWE ciphertext array to the `input_1` lwe
/// ciphertext array.
///
/// # Formal Definition
pub trait LweCiphertextArrayDiscardingSubtractionEngine<InputCiphertextArray, OutputCiphertextArray>:
    AbstractEngine
where
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Subtracts two LWE ciphertext arrays.
    fn discard_sub_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertextArray,
        input_1: &InputCiphertextArray,
        input_2: &InputCiphertextArray,
    ) -> Result<(), LweCiphertextArrayDiscardingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts two LWE ciphertext arrays.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingSubtractionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_sub_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input_1: &InputCiphertextArray,
        input_2: &InputCiphertextArray,
    );
}
