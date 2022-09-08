use crate::prelude::EncoderCount;
use crate::specification::entities::markers::EncoderVectorKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an encoder vector entity.
///
/// # Formal Definition
pub trait EncoderVectorEntity: AbstractEntity<Kind = EncoderVectorKind> {
    /// Returns the number of encoder contained in the vector.
    fn encoder_count(&self) -> EncoderCount;
}
