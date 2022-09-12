use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextArrayEntity;

engine_error! {
    PlaintextArrayDiscardingRetrievalError for PlaintextArrayDiscardingRetrievalEngine @
    PlaintextCountMismatch => "The input and output plaintext count must be the same."
}

impl<EngineError: std::error::Error> PlaintextArrayDiscardingRetrievalError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Value, PlaintextArray>(
        output: &[Value],
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        PlaintextArray: PlaintextArrayEntity,
    {
        if output.len() != input.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines retrieving (discarding) arbitrary values from plaintext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` arbitrary value slice
/// with the element-wise retrieval of the `input` plaintext array values. By arbitrary here, we
/// mean that `Value` can be any type that suits the backend implementor (an integer, a struct
/// wrapping integers, a struct wrapping foreign data or any other
/// thing).
///
/// # Formal Definition
pub trait PlaintextArrayDiscardingRetrievalEngine<PlaintextArray, Value>: AbstractEngine
where
    PlaintextArray: PlaintextArrayEntity,
{
    /// Retrieves arbitrary values from a plaintext array.
    fn discard_retrieve_plaintext_array(
        &mut self,
        output: &mut [Value],
        input: &PlaintextArray,
    ) -> Result<(), PlaintextArrayDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextArrayDiscardingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_retrieve_plaintext_array_unchecked(
        &mut self,
        output: &mut [Value],
        input: &PlaintextArray,
    );
}
