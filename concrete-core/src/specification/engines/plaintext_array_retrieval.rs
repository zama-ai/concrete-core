use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextArrayEntity;

engine_error! {
    PlaintextArrayRetrievalError for PlaintextArrayRetrievalEngine @
}

/// A trait for engines retrieving arbitrary values from plaintext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a vec of arbitrary values from the
/// `input` plaintext array. By arbitrary here, we mean that `Value` can be any type that suits the
/// backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or
/// any other thing).
///
/// # Formal Definition
pub trait PlaintextArrayRetrievalEngine<PlaintextArray, Value>: AbstractEngine
where
    PlaintextArray: PlaintextArrayEntity,
{
    /// Retrieves arbitrary values from a plaintext array.
    fn retrieve_plaintext_array(
        &mut self,
        plaintext: &PlaintextArray,
    ) -> Result<Vec<Value>, PlaintextArrayRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextArrayRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_plaintext_array_unchecked(
        &mut self,
        plaintext: &PlaintextArray,
    ) -> Vec<Value>;
}
