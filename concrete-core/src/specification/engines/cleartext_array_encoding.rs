use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    CleartextArrayEntity, EncoderArrayEntity, PlaintextArrayEntity,
};

engine_error! {
    CleartextArrayEncodingError for CleartextArrayEncodingEngine @
    EncoderCountMismatch => "The encoder count and cleartext count must be the same."
}

impl<EngineError: std::error::Error> CleartextArrayEncodingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<EncoderArray, CleartextArray>(
        encoder_array: &EncoderArray,
        cleartext_array: &CleartextArray,
    ) -> Result<(), Self>
    where
        EncoderArray: EncoderArrayEntity,
        CleartextArray: CleartextArrayEntity,
    {
        if encoder_array.encoder_count().0 != cleartext_array.cleartext_count().0 {
            return Err(Self::EncoderCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encoding cleartext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext array containing the
/// element-wise encodings of the `cleartext_array` cleartext array under the `encoder_array`
/// encoder array.
///
/// # Formal Definition
pub trait CleartextArrayEncodingEngine<EncoderArray, CleartextArray, PlaintextArray>:
    AbstractEngine
where
    EncoderArray: EncoderArrayEntity,
    CleartextArray: CleartextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Encodes a cleartext array into a plaintext array.
    fn encode_cleartext_array(
        &mut self,
        encoder_array: &EncoderArray,
        cleartext_array: &CleartextArray,
    ) -> Result<PlaintextArray, CleartextArrayEncodingError<Self::EngineError>>;

    /// Unsafely encodes a cleartext array into a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextArrayEncodingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encode_cleartext_array_unchecked(
        &mut self,
        encoder_array: &EncoderArray,
        cleartext_array: &CleartextArray,
    ) -> PlaintextArray;
}
