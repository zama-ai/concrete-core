use super::engine_error;
use crate::prelude::EncoderArrayEntity;
use crate::specification::engines::AbstractEngine;

engine_error! {
    EncoderArrayCreationError for EncoderArrayCreationEngine @
}

/// A trait for engines creating encoder arrays from configurations.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an encoder array from the `config`
/// configuration.
///
/// # Formal Definition
pub trait EncoderArrayCreationEngine<Config, EncoderArray>: AbstractEngine
where
    EncoderArray: EncoderArrayEntity,
{
    /// Creates an encoder array from a config.
    fn create_encoder_array_from(
        &mut self,
        config: &[Config],
    ) -> Result<EncoderArray, EncoderArrayCreationError<Self::EngineError>>;

    /// Unsafely creates an encoder array from a config.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`EncoderArrayCreationError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn create_encoder_array_from_unchecked(&mut self, config: &[Config]) -> EncoderArray;
}
