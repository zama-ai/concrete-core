use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayDiscardingOppositeError for LweCiphertextArrayDiscardingOppositeEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingOppositeError<EngineError> {
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

/// A trait for engines computing the opposite (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the element-wise opposite of the `input` LWE ciphertext array.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextDiscardingOppositeEngine`)
pub trait LweCiphertextArrayDiscardingOppositeEngine<InputCiphertextArray, OutputCiphertextArray>:
    AbstractEngine
where
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Computes the opposite of an LWE ciphertext array.
    fn discard_opp_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
    ) -> Result<(), LweCiphertextArrayDiscardingOppositeError<Self::EngineError>>;

    /// Unsafely computes the opposite of an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingOppositeError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_opp_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
    );
}
