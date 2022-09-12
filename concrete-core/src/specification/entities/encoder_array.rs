use crate::prelude::EncoderCount;
use crate::specification::entities::markers::EncoderArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an encoder array entity.
///
/// # Formal Definition
pub trait EncoderArrayEntity: AbstractEntity<Kind = EncoderArrayKind> {
    /// Returns the number of encoder contained in the array.
    fn encoder_count(&self) -> EncoderCount;
}
