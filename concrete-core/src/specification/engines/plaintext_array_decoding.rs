use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    CleartextArrayEntity, EncoderArrayEntity, PlaintextArrayEntity,
};

engine_error! {
    PlaintextArrayDecodingError for PlaintextArrayDecodingEngine @
    EncoderCountMismatch => "The encoder count and plaintext count must be the same."
}

impl<EngineError: std::error::Error> PlaintextArrayDecodingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<EncoderArray, PlaintextArray>(
        encoder: &EncoderArray,
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        EncoderArray: EncoderArrayEntity,
        PlaintextArray: PlaintextArrayEntity,
    {
        if input.plaintext_count().0 != encoder.encoder_count().0 {
            return Err(Self::EncoderCountMismatch);
        }
        Ok(())
    }
}
/// A trait for engines decoding plaintext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext array containing the
/// element-wise decodings of the `input` plaintext array, under the `encoder` encoder array.
///
/// # Formal Definition
pub trait PlaintextArrayDecodingEngine<EncoderArray, PlaintextArray, CleartextArray>:
    AbstractEngine
where
    EncoderArray: EncoderArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
    CleartextArray: CleartextArrayEntity,
{
    /// Decodes a plaintext array.
    fn decode_plaintext_array(
        &mut self,
        encoder: &EncoderArray,
        input: &PlaintextArray,
    ) -> Result<CleartextArray, PlaintextArrayDecodingError<Self::EngineError>>;

    /// Unsafely decodes a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextArrayDecodingError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn decode_plaintext_array_unchecked(
        &mut self,
        encoder: &EncoderArray,
        input: &PlaintextArray,
    ) -> CleartextArray;
}
