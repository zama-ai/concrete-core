use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextArrayEntity;

engine_error! {
    CleartextArrayDiscardingRetrievalError for CleartextArrayDiscardingRetrievalEngine @
    CleartextCountMismatch => "The input and output cleartext count must be the same."
}

impl<EngineError: std::error::Error> CleartextArrayDiscardingRetrievalError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Value, CleartextArray>(
        output: &[Value],
        input: &CleartextArray,
    ) -> Result<(), Self>
    where
        CleartextArray: CleartextArrayEntity,
    {
        if output.len() != input.cleartext_count().0 {
            return Err(Self::CleartextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines retrieving (discarding) arbitrary values from cleartext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` arbitrary value slice
/// with the element-wise retrieval of the `input` cleartext array values. By arbitrary here, we
/// mean that `Value` can be any type that suits the backend implementor (an integer, a struct
/// wrapping integers, a struct wrapping foreign data or any other thing).
///
/// # Formal Definition
pub trait CleartextArrayDiscardingRetrievalEngine<CleartextArray, Value>: AbstractEngine
where
    CleartextArray: CleartextArrayEntity,
{
    /// Retrieves arbitrary values from a cleartext array.
    fn discard_retrieve_cleartext_array(
        &mut self,
        output: &mut [Value],
        input: &CleartextArray,
    ) -> Result<(), CleartextArrayDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a cleartext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextArrayDiscardingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_retrieve_cleartext_array_unchecked(
        &mut self,
        output: &mut [Value],
        input: &CleartextArray,
    );
}
