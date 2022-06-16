use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweSecretKeyEntity;

engine_error! {
    GlweSecretKeyTensorProductSameKeyError for
    GlweSecretKeyTensorProductSameKeyEngine @
}

/// A trait for engines to perform the tensor product of a GLWE secret key with itself
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates the tensor product of a GLWE secret
/// key `input` with itself.
///
/// # Formal Definition
///
/// This function takes as input a
/// [`GLWE secret key`](`crate::specification::entities::GlweSecretKeyEntity`)
/// $\mathsf{S} = (S\_{1}, S\_{2}, \dots, S\_{k}) $ and outputs a
/// [`GLWE secret key`](`crate::specification::entities::GlweSecretKeyEntity`)
/// which contains the tensor product of the input secret key with itself.
/// In particular, the function outputs a GLWE secret key of the form:
///
/// $(S^{\prime}\_1, S^{\prime}\_2, \dots, S^{\prime}\_{(k + k \cdot (k + 1) / 2 + k)})$
/// where the ordering of the terms is as follows:
///
/// $(S\_1^{2}, S\_1, S\_{2}^2, S\_2, S\_{1}S\_{2}, S\_{3}^2, S\_3, S\_{1}S\_{3}, S\_{2}S\_{3},
/// \dots, S\_{k}^2, S\_k, S\_{1}S\_{k}, \dots, S\_{k-1}S\_{k})$.
pub trait GlweSecretKeyTensorProductSameKeyEngine<InputKey, OutputKey>: AbstractEngine
where
    InputKey: GlweSecretKeyEntity,
    OutputKey: GlweSecretKeyEntity,
{
    /// performs the tensor product of a GLWE secret key with itself.
    fn create_tensor_product_glwe_secret_key_same_key(
        &mut self,
        input: &InputKey,
    ) -> Result<OutputKey, GlweSecretKeyTensorProductSameKeyError<Self::EngineError>>;

    /// Unsafely performs the tensor product of a GLWE secret key with itself.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSecretKeyTensorProductSameKeyError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.

    unsafe fn create_tensor_product_glwe_secret_key_same_key_unchecked(
        &mut self,
        input: &InputKey,
    ) -> OutputKey;
}
