use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextArrayEntity;

engine_error! {
    PlaintextArrayConversionError for PlaintextArrayConversionEngine @
}

/// A trait for engines converting plaintext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext array containing the
/// conversion of the `input` plaintext array to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait PlaintextArrayConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextArrayEntity,
    Output: PlaintextArrayEntity,
{
    /// Converts a plaintext array.
    fn convert_plaintext_array(
        &mut self,
        input: &Input,
    ) -> Result<Output, PlaintextArrayConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextArrayConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_plaintext_array_unchecked(&mut self, input: &Input) -> Output;
}
