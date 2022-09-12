use crate::prelude::CleartextCount;
use crate::specification::entities::markers::CleartextArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a cleartext array entity.
///
/// # Formal Definition
pub trait CleartextArrayEntity: AbstractEntity<Kind = CleartextArrayKind> {
    /// Returns the number of cleartext contained in the array.
    fn cleartext_count(&self) -> CleartextCount;
}
