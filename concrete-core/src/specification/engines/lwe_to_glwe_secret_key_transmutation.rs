use super::engine_error;
use crate::prelude::AbstractEngine;
use concrete_commons::parameters::PolynomialSize;

use crate::specification::entities::{GlweSecretKeyEntity, LweSecretKeyEntity};

engine_error! {
    LweToGlweSecretKeyTransmutationEngineError for LweToGlweSecretKeyTransmutationEngine @
    IncompatibleLweDimension => "The input key LweDimension is not compatible \
                                 with the provided PolynomialSize",
    NullPolynomialSize => "The output secret key polynomial size must be greater than zero.",
    SizeOnePolynomial => "The output secret key polynomial size must be greater than one. Otherwise\
                          you should prefer the LWE scheme."
}

impl<EngineError: std::error::Error> LweToGlweSecretKeyTransmutationEngineError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputKey>(
        lwe_secret_key: &InputKey,
        polynomial_size: PolynomialSize,
    ) -> Result<(), Self>
    where
        InputKey: LweSecretKeyEntity,
    {
        if polynomial_size.0 == 0 {
            return Err(Self::NullPolynomialSize);
        }
        if polynomial_size.0 == 1 {
            return Err(Self::SizeOnePolynomial);
        }
        if lwe_secret_key.lwe_dimension().0 % polynomial_size.0 != 0 {
            return Err(Self::IncompatibleLweDimension);
        }
        Ok(())
    }
}

/// A trait for engines transmuting LWE secret keys into GLWE secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing LWE into a fresh GLWE secret
/// key.
pub trait LweToGlweSecretKeyTransmutationEngine<InputKey, OutputKey>: AbstractEngine
where
    InputKey: LweSecretKeyEntity,
    OutputKey: GlweSecretKeyEntity<KeyDistribution = InputKey::KeyDistribution>,
{
    /// Does the transmutation of the LWE secret key into a GLWE secret key
    fn transmute_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_secret_key: InputKey,
        polynomial_size: PolynomialSize,
    ) -> Result<OutputKey, LweToGlweSecretKeyTransmutationEngineError<Self::EngineError>>;

    /// Unsafely transmutes an LWE secret key into a GLWE secret key
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweToGlweSecretKeyTransmutationEngineError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transmute_lwe_secret_key_to_glwe_secret_key_unchecked(
        &mut self,
        lwe_secret_key: InputKey,
        polynomial_size: PolynomialSize,
    ) -> OutputKey;
}
