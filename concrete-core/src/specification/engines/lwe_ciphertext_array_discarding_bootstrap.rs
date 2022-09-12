use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{
    GlweCiphertextArrayEntity, LweBootstrapKeyEntity, LweCiphertextArrayEntity,
};

engine_error! {
    LweCiphertextArrayDiscardingBootstrapError for LweCiphertextArrayDiscardingBootstrapEngine @
    InputLweDimensionMismatch => "The input array and key input LWE dimension must be the same.",
    OutputLweDimensionMismatch => "The output array and key output LWE dimension must be the same.",
    AccumulatorGlweDimensionMismatch => "The accumulator array and key GLWE dimension must be the same.",
    AccumulatorPolynomialSizeMismatch => "The accumulator array and key polynomial size must be the same.",
    AccumulatorCountMismatch => "The accumulator count and input ciphertext count must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingBootstrapError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<
        BootstrapKey,
        AccumulatorArray,
        InputCiphertextArray,
        OutputCiphertextArray,
    >(
        output: &OutputCiphertextArray,
        input: &InputCiphertextArray,
        acc: &AccumulatorArray,
        bsk: &BootstrapKey,
    ) -> Result<(), Self>
    where
        BootstrapKey: LweBootstrapKeyEntity,
        AccumulatorArray: GlweCiphertextArrayEntity,
        InputCiphertextArray: LweCiphertextArrayEntity,
        OutputCiphertextArray: LweCiphertextArrayEntity,
    {
        if bsk.input_lwe_dimension() != input.lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if bsk.output_lwe_dimension() != output.lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }

        if bsk.glwe_dimension() != acc.glwe_dimension() {
            return Err(Self::AccumulatorGlweDimensionMismatch);
        }

        if bsk.polynomial_size() != acc.polynomial_size() {
            return Err(Self::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_ciphertext_count().0 != input.lwe_ciphertext_count().0 {
            return Err(Self::AccumulatorCountMismatch);
        }

        if input.lwe_ciphertext_count() != output.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines bootstrapping (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the element-wise bootstrap of the `input` LWE ciphertext array, using the `acc`
/// accumulator as lookup-table, and the `bsk` bootstrap key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextDiscardingBootstrapEngine`)
pub trait LweCiphertextArrayDiscardingBootstrapEngine<
    BootstrapKey,
    AccumulatorArray,
    InputCiphertextArray,
    OutputCiphertextArray,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    AccumulatorArray: GlweCiphertextArrayEntity,
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Bootstraps an LWE ciphertext array.
    fn discard_bootstrap_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
        acc: &AccumulatorArray,
        bsk: &BootstrapKey,
    ) -> Result<(), LweCiphertextArrayDiscardingBootstrapError<Self::EngineError>>;

    /// Unsafely bootstraps an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingBootstrapError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_bootstrap_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
        acc: &AccumulatorArray,
        bsk: &BootstrapKey,
    );
}
