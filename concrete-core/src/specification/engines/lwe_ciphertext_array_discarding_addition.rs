use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayDiscardingAdditionError for LweCiphertextArrayDiscardingAdditionEngine @
    LweDimensionMismatch => "The input and output LWE dimensions must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingAdditionError<EngineError> {
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

/// A trait for engines adding (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the element-wise addition of the `input_1` LWE ciphertext array and the `input_2` lwe
/// ciphertext array.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextDiscardingAdditionEngine`)
pub trait LweCiphertextArrayDiscardingAdditionEngine<InputCiphertextArray, OutputCiphertextArray>:
    AbstractEngine
where
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Adds two LWE ciphertext arrays.
    fn discard_add_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertextArray,
        input_1: &InputCiphertextArray,
        input_2: &InputCiphertextArray,
    ) -> Result<(), LweCiphertextArrayDiscardingAdditionError<Self::EngineError>>;

    /// Unsafely adds two LWE ciphertext arrays.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingAdditionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_add_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input_1: &InputCiphertextArray,
        input_2: &InputCiphertextArray,
    );
}
