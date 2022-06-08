use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweSecretKeyEntity;

engine_error! {
    GlweSecretKeyTensorProductSameKeyError for
    GlweSecretKeyTensorProductSameKeyEngine @
}

/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates the tensor product of a GLWE secret
/// key `input` with itself.
///
/// # Formal Definition
///
/// This function takes as input a
/// [`GLWE secret key`](`crate::specification::entities::GlweSecretKeyEntity`)
/// $\mathsf{s} = (s\_{1}, s\_{2}, \dots, s\_{k}) $
/// [`GLWE secret key`](`crate::specification::entities::GlweSecretKeyEntity`)
/// contains the tensor product of the input secret key with itself.
/// In particular, the function outputs a GLWE secret key of the form
///
/// $(s^{\prime}\_1, s^{\prime}\_2, \dots, s^{\prime}\_{(k + k \cdot (k + 1) / 2 + k)})$
/// where the ordering of the terms is as follows:
///
/// $(s\_1^{2}, s\_1, s\_{2}^2, s\_2, s\_{1}s\_{2}, s\_{3}^2, s\_3, s\_{1}s\_{3}, s\_{2}s\_{3},
/// \dots, s\_{k}^2, s\_k, s\_{1}s\_{k}, \dots, s\_{k-1}s\_{k})$.
///
pub trait GlweSecretKeyTensorProductSameKeyEngine<InputKey, OutputKey>: AbstractEngine
where
    InputKey: GlweSecretKeyEntity,
    OutputKey: GlweSecretKeyEntity,
{
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
