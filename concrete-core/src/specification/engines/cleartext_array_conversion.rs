use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextArrayEntity;

engine_error! {
    CleartextArrayConversionError for CleartextArrayConversionEngine @
}

/// A trait for engines converting (discard) cleartext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext array containing the
/// conversion of the `input` cleartext array to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait CleartextArrayConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextArrayEntity,
    Output: CleartextArrayEntity,
{
    /// Converts a cleartext array.
    fn convert_cleartext_array(
        &mut self,
        input: &Input,
    ) -> Result<Output, CleartextArrayConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextArrayConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_cleartext_array_unchecked(&mut self, input: &Input) -> Output;
}
