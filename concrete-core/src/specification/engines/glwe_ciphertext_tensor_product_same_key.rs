use super::engine_error;
use crate::prelude::markers::TensorProductKeyDistribution;
use crate::prelude::ScalingFactor;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextTensorProductSameKeyError for GlweCiphertextTensorProductSameKeyEngine @
    PolynomialSizeMismatch => "The polynomial size of the input and output GLWE ciphertexts must be\
     the same.",
    ZeroScalingFactorError => "The scaling factor for the tensor product must be stricly greater \
    than\
     zero.",
    InputGlweDimensionMismatch => "The GLWE dimension of the input ciphertexts must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextTensorProductSameKeyError<EngineError> {
    pub fn perform_generic_checks<InputCiphertext1, InputCiphertext2>(
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        scale: ScalingFactor,
    ) -> Result<(), Self>
    where
        InputCiphertext1: GlweCiphertextEntity,
        InputCiphertext2: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
    {
        if scale.0 == 0 {
            return Err(Self::ZeroScalingFactorError);
        }
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
///
/// This function takes as input two
/// [`GLWE ciphertexts`](`crate::specification::entities::GlweCiphertextEntity`)
/// $\mathsf{c}\_1 = \mathsf{GLWE}\_{\vec{S}}(
/// \mathsf{m}\_1)  = (A\_{1,1}, \dots, A\_{1,k}, B\_1)$ and $\mathsf{c}\_2 =
/// \mathsf{GLWE}\_{\vec{S}}( \mathsf{m}_2 ) = (A\_{2,1}, \dots, A\_{2,k}, B\_2)$ encrypted with the
/// same key $\vec{S}$ and outputs a
/// [`GLWE ciphertext`](`crate::specification::entities::GlweCiphertextEntity`) which
/// contains the tensor product of the two ciphertexts. In particular, the output GLWE ciphertext is
/// of the form:
///
/// $(A^{\prime}\_1, A^{\prime}\_2, \dots, A^{\prime}\_{(k + k \cdot (k + 1) / 2 + k)}, B^{\prime})$
/// where the ordering of the terms is as follows:
///
/// $(T\_1, A\_1, T\_2, A\_2, R\_{1,2}, T\_3, A\_3, R\_{1,3}, R\_{2,3}, \dots,
/// T\_k, A\_k, R\_{1,k}, \dots, R\_{k-1, k}, B^{\prime})$.
///
/// each $T\_i$ is of the form:
/// $\left[ \left\lfloor \frac{[A\_{1,i} \cdot A\_{2,i}]\_Q}{\Delta} \right\rceil \right]\_q$,
///
/// each $A\_{i}^\prime$ is of the form:
/// $\left[ \left\lfloor \frac{[A\_{1,i} \cdot A\_{2,j} + A\_{1,j} \cdot A\_{2,i} ]\_Q}{\Delta}
/// \right\rceil \right]\_q$,
///
/// each $R\_{i,j}$ is of the form:
/// $\left[ \left\lfloor \frac{[A\_{1,i} \cdot B_2 + B_1 \cdot A\_{2,i}]\_Q}{\Delta} \right\rceil
/// \right]\_q$,
///
/// and $B^{\prime} = \left[ \left\lfloor \frac{[B_1 \cdot B_2]\_Q}{\Delta} \right\rceil
/// \right]\_q$.
pub trait GlweCiphertextTensorProductSameKeyEngine<
    InputCiphertext1,
    InputCiphertext2,
    OutputCiphertext,
>: AbstractEngine where
    InputCiphertext1: GlweCiphertextEntity,
    InputCiphertext2: GlweCiphertextEntity<KeyDistribution = InputCiphertext1::KeyDistribution>,
    OutputCiphertext: GlweCiphertextEntity<KeyDistribution = TensorProductKeyDistribution>,
{
    /// performs a tensor product of two GLWE ciphertexts **encrypted with the SAME KEY**.
    fn tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &InputCiphertext1,
        input2: &InputCiphertext2,
        scale: ScalingFactor,
    ) -> Result<OutputCiphertext, GlweCiphertextTensorProductSameKeyError<Self::EngineError>>;

    /// Unsafely performs a tensor product of two GLWE ciphertexts **encrypted with the SAME KEY**.
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
