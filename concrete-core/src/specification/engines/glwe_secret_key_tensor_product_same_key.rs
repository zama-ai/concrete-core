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
/// The goal of this function is to take as input a GLWE secret key, and
/// and output the tensor product with itself.
/// // TODO describe the math
/// //   don't forget that in the rust doc every _ latex symbol has to be replaced by \_
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
    /// of [`TensorProductGlweSecretKeyCreationError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.

    unsafe fn create_tensor_product_glwe_secret_key_same_key_unchecked(
        &mut self,
        input: &InputKey,
    ) -> OutputKey;
}
