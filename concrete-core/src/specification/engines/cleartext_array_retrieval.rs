use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextArrayEntity;

engine_error! {
    CleartextArrayRetrievalError for CleartextArrayRetrievalEngine @
}

/// A trait for engines retrieving arbitrary values from cleartext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a vec of arbitrary values from the
/// `input` cleartext array. By arbitrary here, we mean that `Value` can be any type that suits the
/// backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or
/// any other thing).
///
/// # Formal Definition
pub trait CleartextArrayRetrievalEngine<CleartextArray, Value>: AbstractEngine
where
    CleartextArray: CleartextArrayEntity,
{
    /// Retrieves arbitrary values from a cleartext array.
    fn retrieve_cleartext_array(
        &mut self,
        cleartext: &CleartextArray,
    ) -> Result<Vec<Value>, CleartextArrayRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a cleartext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextArrayRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_cleartext_array_unchecked(
        &mut self,
        cleartext: &CleartextArray,
    ) -> Vec<Value>;
}
