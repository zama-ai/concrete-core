use crate::commons::crypto::encoding::FloatEncoder;
use crate::prelude::markers::EncoderArrayKind;
use crate::prelude::{AbstractEntity, EncoderArrayEntity, EncoderCount};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// An encoder for 64 bits floating point numbers.
#[derive(Debug, PartialEq)]
pub struct FloatEncoderArray(pub(crate) Vec<FloatEncoder>);

impl AbstractEntity for FloatEncoderArray {
    type Kind = EncoderArrayKind;
}
impl EncoderArrayEntity for FloatEncoderArray {
    fn encoder_count(&self) -> EncoderCount {
        EncoderCount(self.0.len())
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FloatEncoderArrayVersion {
    V0,
    #[serde(other)]
    Unsupported,
}
