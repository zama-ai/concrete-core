use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{CleartextVectorEntity, LweCiphertextVectorEntity};

engine_error! {
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationError for LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine @
    LweDimensionMismatch => "The input and output ciphertext vector LWE dimension must be the \
    same.",
    CleartextCountMismatch => "The input LWE and cleartext vectors count must be the same"
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertextVector, OutputCiphertextVector, CleartextVector>(
        output: &OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &CleartextVector,
    ) -> Result<(), Self>
    where
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
        CleartextVector: CleartextVectorEntity,
    {
        if output.lwe_dimension() != input_1.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        if input_1.lwe_ciphertext_count().0 != input_2.cleartext_count().0 {
            return Err(Self::CleartextCountMismatch);
        }
        Ok(())
    }
}

pub trait LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine<
    InputCiphertextVector,
    CleartextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    CleartextVector: CleartextVectorEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Multiply an LWE ciphertext vector with a cleartext vector.
    fn discard_mul_lwe_ciphertext_vector_cleartext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &CleartextVector,
    ) -> Result<
        (),
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError<Self::EngineError>,
    >;

    /// Unsafely multiply an LWE ciphertext vector with a cleartext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorCleartextVectorDiscardingMultiplicationError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &CleartextVector,
    );
}
