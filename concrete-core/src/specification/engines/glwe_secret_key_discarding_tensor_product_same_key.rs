use super::engine_error;
use crate::prelude::markers::TensorProductKeyDistribution;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweSecretKeyEntity;

engine_error! {
    GlweSecretKeyDiscardingTensorProductSameKeyError for
    GlweSecretKeyDiscardingTensorProductSameKeyEngine @
    PolynomialSizeMismatch => "The polynomial size of the input and the output is not the same",
    GlweDimensionMismatch => "The GLWE dimension of the output is incorrect"
}

impl<EngineError: std::error::Error> GlweSecretKeyDiscardingTensorProductSameKeyError<EngineError> {
    pub fn perform_generic_checks<InputKey, OutputKey>(
        input: &InputKey,
        output: &OutputKey,
    ) -> Result<(), Self>
    where
        InputKey: GlweSecretKeyEntity,
        OutputKey: GlweSecretKeyEntity<KeyDistribution = TensorProductKeyDistribution>,
    {
        if input.polynomial_size().0 != output.polynomial_size().0 {
            return Err(Self::PolynomialSizeMismatch);
        }
        if 2 * output.glwe_dimension().0
            != input.glwe_dimension().0 * (3 + input.glwe_dimension().0)
        {
            return Err(Self::GlweDimensionMismatch);
        }
        Ok(())
    }
}
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation generates the tensor product of a GLWE
/// secret key `input` with itself, and stores the result in `output`.
///
/// # Formal Definition
///
/// //TODO Ben add link
/// Check []
pub trait GlweSecretKeyDiscardingTensorProductSameKeyEngine<InputKey, OutputKey>:
    AbstractEngine
where
    InputKey: GlweSecretKeyEntity,
    OutputKey: GlweSecretKeyEntity<KeyDistribution = TensorProductKeyDistribution>,
{
    fn discard_tensor_product_glwe_secret_key_same_key(
        &mut self,
        input: &InputKey,
        output: &mut OutputKey,
    ) -> Result<(), GlweSecretKeyDiscardingTensorProductSameKeyError<Self::EngineError>>;

    /// Unsafely performs a tensor product of a GLWE secret key with itself.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweKeyDiscardingTensorProductError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.

    unsafe fn discard_tensor_product_glwe_secret_key_same_key_unchecked(
        &mut self,
        input: &InputKey,
        output: &mut OutputKey,
    );
}
