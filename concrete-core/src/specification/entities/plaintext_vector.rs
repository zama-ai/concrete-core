use crate::prelude::PlaintextCount;
use crate::specification::entities::markers::PlaintextVectorKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a plaintext vector.
///
/// # Formal Definition
pub trait PlaintextVectorEntity: AbstractEntity<Kind = PlaintextVectorKind> {
    /// Returns the number of plaintext contained in the vector.
    fn plaintext_count(&self) -> PlaintextCount;
}
