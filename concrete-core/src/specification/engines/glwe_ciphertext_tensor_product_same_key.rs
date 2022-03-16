use super::engine_error;
use crate::prelude::markers::TensorProductKeyDistribution;
use crate::prelude::ScalingFactor;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextTensorProductSameKeyError for GlweCiphertextTensorProductSameKeyEngine @
    PolynomialSizeMismatch => "The polynomial size of the input and output GLWE ciphertexts must be\
     the same.",
    InputGlweDimensionMismatch => "The GLWE dimension of the input ciphertexts must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextTensorProductSameKeyError<EngineError> {
    pub fn perform_generic_checks<InputCiphertext1, InputCiphertext2>(
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
    ) -> Result<(), Self>
    where
        InputCiphertext1: GlweCiphertextEntity,
        InputCiphertext2: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
    {
        if input1.polynomial_size().0 != input2.polynomial_size().0 {
            return Err(Self::PolynomialSizeMismatch);
        }
        if input1.glwe_dimension().0 != input2.glwe_dimension().0 {
            return Err(Self::InputGlweDimensionMismatch);
        }
        Ok(())
    }
}
/// A trait for engines multiplying GLWE ciphertexts **encrypted with the SAME KEY**.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext with
/// the tensor product of the `input` GLWE ciphertexts.
///
/// # Formal Definition
/// // TODO add documentation
pub trait GlweCiphertextTensorProductSameKeyEngine<
    InputCiphertext1,
    InputCiphertext2,
    OutputCiphertext,
>: AbstractEngine where
    InputCiphertext1: GlweCiphertextEntity,
    InputCiphertext2: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
    OutputCiphertext: GlweCiphertextEntity<KeyDistribution = TensorProductKeyDistribution>,
{
    fn tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        scale: ScalingFactor,
    ) -> Result<OutputCiphertext, GlweCiphertextTensorProductSameKeyError<Self::EngineError>>;

    /// Unsafely performs a tesnro product of two GLWE ciphertexts **encrypted with the SAME KEY**.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextTensorProductSameKeyError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn tensor_product_glwe_ciphertext_same_key_unchecked(
        &mut self,
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        scale: ScalingFactor,
    ) -> OutputCiphertext;
}
