use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextArrayEntity;

engine_error! {
    PlaintextArrayDiscardingConversionError for PlaintextArrayDiscardingConversionEngine @
    PlaintextCountMismatch => "The input and output plaintext count must be the same"
}

impl<EngineError: std::error::Error> PlaintextArrayDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: PlaintextArrayEntity,
        Output: PlaintextArrayEntity,
    {
        if input.plaintext_count() != output.plaintext_count() {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines converting (discarding) plaintext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext array with
/// the conversion of the `input` plaintext array to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait PlaintextArrayDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextArrayEntity,
    Output: PlaintextArrayEntity,
{
    /// Converts a plaintext array .
    fn discard_convert_plaintext_array(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), PlaintextArrayDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext array .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextArrayDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_plaintext_array_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
