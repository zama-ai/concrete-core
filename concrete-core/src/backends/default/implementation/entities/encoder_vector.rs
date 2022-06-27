use crate::commons::crypto::encoding::FloatEncoder;
use crate::prelude::markers::EncoderVectorKind;
use crate::prelude::{AbstractEntity, EncoderVectorEntity};
use concrete_commons::parameters::EncoderCount;
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// An encoder for 64 bits floating point numbers.
#[derive(Debug, PartialEq)]
pub struct FloatEncoderVector(pub(crate) Vec<FloatEncoder>);

impl AbstractEntity for FloatEncoderVector {
    type Kind = EncoderVectorKind;
}
impl EncoderVectorEntity for FloatEncoderVector {
    fn encoder_count(&self) -> EncoderCount {
        EncoderCount(self.0.len())
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FloatEncoderVectorVersion {
    V0,
    #[serde(other)]
    Unsupported,
}
