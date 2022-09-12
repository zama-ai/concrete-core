use crate::prelude::PlaintextCount;
use crate::specification::entities::markers::PlaintextArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a plaintext array.
///
/// # Formal Definition
pub trait PlaintextArrayEntity: AbstractEntity<Kind = PlaintextArrayKind> {
    /// Returns the number of plaintext contained in the array.
    fn plaintext_count(&self) -> PlaintextCount;
}
