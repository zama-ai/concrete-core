use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextVectorEntity, PlaintextVectorEntity};

engine_error! {
    LweCiphertextVectorPlaintextVectorDiscardingAdditionError for
    LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine @
    LweDimensionMismatch => "The input and output ciphertext vector LWE dimensions must be the \
    same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same.",
    PlaintextCountMismatch => "The input ciphertext and plaintext count must be the same."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorPlaintextVectorDiscardingAdditionError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<
        InputCiphertextVector,
        InputPlaintextVector,
        OutputCiphertextVector,
    >(
        output: &OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &InputPlaintextVector,
    ) -> Result<(), Self>
    where
        InputCiphertextVector: LweCiphertextVectorEntity,
        InputPlaintextVector: PlaintextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if input_1.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        if output.lwe_ciphertext_count() != input_1.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        if input_1.lwe_ciphertext_count().0 != input_2.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines adding (discarding) plaintext vectors to LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the addition of the `input_1` LWE ciphertext vector with the `input_2` plaintext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine<
    InputCiphertextVector,
    PlaintextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    PlaintextVector: PlaintextVectorEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Adds a plaintext vector to an LWE ciphertext vector.
    fn discard_add_lwe_ciphertext_vector_plaintext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &PlaintextVector,
    ) -> Result<(), LweCiphertextVectorPlaintextVectorDiscardingAdditionError<Self::EngineError>>;

    /// Unsafely adds a plaintext vector to an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorPlaintextVectorDiscardingAdditionError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_add_lwe_ciphertext_vector_plaintext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &PlaintextVector,
    );
}
