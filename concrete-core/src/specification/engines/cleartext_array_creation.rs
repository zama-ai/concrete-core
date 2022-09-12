use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextArrayEntity;

engine_error! {
    CleartextArrayCreationError for CleartextArrayCreationEngine @
    EmptyInput => "The input slice must not be empty."
}

impl<EngineError: std::error::Error> CleartextArrayCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Value>(values: &[Value]) -> Result<(), Self> {
        if values.is_empty() {
            return Err(Self::EmptyInput);
        }
        Ok(())
    }
}

/// A trait for engines creating cleartext arrays from arbitrary values.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext array from the `value`
/// slice of arbitrary values. By arbitrary here, we mean that `Value` can be any type that suits
/// the backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data
/// or any other thing).
///
/// # Formal Definition
pub trait CleartextArrayCreationEngine<Value, CleartextArray>: AbstractEngine
where
    CleartextArray: CleartextArrayEntity,
{
    /// Creates a cleartext array from a slice of arbitrary values.
    fn create_cleartext_array_from(
        &mut self,
        values: &[Value],
    ) -> Result<CleartextArray, CleartextArrayCreationError<Self::EngineError>>;

    /// Unsafely creates a cleartext array from a slice of arbitrary values.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextArrayCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_cleartext_array_from_unchecked(&mut self, values: &[Value]) -> CleartextArray;
}
