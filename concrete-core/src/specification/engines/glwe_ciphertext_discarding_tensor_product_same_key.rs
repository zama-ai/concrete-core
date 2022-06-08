use super::engine_error;
use crate::prelude::ScalingFactor;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextDiscardingTensorProductSameKeyError for GlweCiphertextDiscardingTensorProductSameKeyEngine @
    PolynomialSizeMismatch => "The polynomial size of the input and output GLWE ciphertexts must be\
     the same.",
    InputGlweDimensionMismatch => "The GLWE dimension of the input ciphertexts must be the same.",
    OutputGlweDimensionMismatch => "The GLWE dimension of the output ciphertext is incorrect"
}

impl<EngineError: std::error::Error>
    GlweCiphertextDiscardingTensorProductSameKeyError<EngineError>
{
    pub fn perform_generic_checks<InputCiphertext1, InputCiphertext2, OutputCiphertext>(
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        output: &OutputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext1: GlweCiphertextEntity,
        InputCiphertext2: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
        OutputCiphertext: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
    {
        if input1.polynomial_size().0 != input2.polynomial_size().0
            || input1.polynomial_size().0 != output.polynomial_size().0
        {
            return Err(Self::PolynomialSizeMismatch);
        }
        if input1.glwe_dimension().0 != input2.glwe_dimension().0 {
            return Err(Self::InputGlweDimensionMismatch);
        }
        if 2 * output.glwe_dimension().0
            != input1.glwe_dimension().0 * (3 + input1.glwe_dimension().0)
        {
            return Err(Self::OutputGlweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines performing a (discarding) tensor product on GLWE ciphertexts encrypted
/// using the exact same key.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext with
/// the tensor product of the `input` GLWE ciphertexts encrypted using the exact same key.
///
///
/// # Formal Definition
/// The formal definition is as in the
/// [GlweCiphertextTensorProductSameKeyEngine][crate::specification::engines::GlweCiphertextTensorProductSameKeyEngine`]
pub trait GlweCiphertextDiscardingTensorProductSameKeyEngine<
    InputCiphertext1,
    InputCiphertext2,
    OutputCiphertext,
>: AbstractEngine where
    InputCiphertext1: GlweCiphertextEntity,
    InputCiphertext2: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
    OutputCiphertext: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
{
    fn discard_tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        output: &mut OutputCiphertext,
        scale: ScalingFactor,
    ) -> Result<(), GlweCiphertextDiscardingTensorProductSameKeyError<Self::EngineError>>;

    /// Unsafely performs a discarding tensor product of two GLWE ciphertexts encrypted using the
    /// exact same key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextDiscardingTensorProductSameKeyError`]. For safety concerns _specific_ to
    /// an engine, refer to the implementer safety section.

    unsafe fn discard_tensor_product_glwe_ciphertext_same_key_unchecked(
        &mut self,
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        output: &mut OutputCiphertext,
        scale: ScalingFactor,
    );
}
