use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextArrayEntity;

engine_error! {
    CleartextArrayDiscardingConversionError for CleartextArrayDiscardingConversionEngine @
    CleartextCountMismatch => "The input and output cleartext count must be the same"
}

impl<EngineError: std::error::Error> CleartextArrayDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: CleartextArrayEntity,
        Output: CleartextArrayEntity,
    {
        if output.cleartext_count() != input.cleartext_count() {
            return Err(Self::CleartextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines converting (discarding) cleartexts array.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` cleartext array with
/// the conversion of the `input` cleartext array to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait CleartextArrayDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextArrayEntity,
    Output: CleartextArrayEntity,
{
    /// Converts a cleartext array .
    fn discard_convert_cleartext_array(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), CleartextArrayDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextArrayDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_cleartext_array_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
