use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    CleartextArrayEntity, LweCiphertextArrayEntity, LweCiphertextEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextArrayDiscardingAffineTransformationError for LweCiphertextArrayDiscardingAffineTransformationEngine @
    LweDimensionMismatch => "The output and inputs LWE dimensions must be the same.",
    CleartextCountMismatch => "The cleartext array count and input array count must be the same."
}
impl<EngineError: std::error::Error>
    LweCiphertextArrayDiscardingAffineTransformationError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<CiphertextArray, CleartextArray, OutputCiphertext>(
        output: &OutputCiphertext,
        inputs: &CiphertextArray,
        weights: &CleartextArray,
    ) -> Result<(), Self>
    where
        OutputCiphertext: LweCiphertextEntity,
        CiphertextArray: LweCiphertextArrayEntity,
        CleartextArray: CleartextArrayEntity,
    {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(Self::CleartextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines performing (discarding) affine transformation of LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the result of the affine tranform of the `inputs` LWE ciphertext array, with the `weights`
/// cleartext array and the `bias` plaintext.
///
/// # Formal Definition
pub trait LweCiphertextArrayDiscardingAffineTransformationEngine<
    CiphertextArray,
    CleartextArray,
    Plaintext,
    OutputCiphertext,
>: AbstractEngine where
    OutputCiphertext: LweCiphertextEntity,
    CiphertextArray: LweCiphertextArrayEntity,
    CleartextArray: CleartextArrayEntity,
    Plaintext: PlaintextEntity,
{
    /// Performs the affine transform of an LWE ciphertext array.
    fn discard_affine_transform_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertext,
        inputs: &CiphertextArray,
        weights: &CleartextArray,
        bias: &Plaintext,
    ) -> Result<(), LweCiphertextArrayDiscardingAffineTransformationError<Self::EngineError>>;

    /// Unsafely performs the affine transform of an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingAffineTransformationError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_affine_transform_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        inputs: &CiphertextArray,
        weights: &CleartextArray,
        bias: &Plaintext,
    );
}
