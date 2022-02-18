use concrete_commons::parameters::EncoderCount;
use crate::backends::core::private::crypto::encoding::CryptoApiEncoder;
use crate::prelude::{AbstractEntity, EncoderEntity, EncoderVectorEntity};
use crate::prelude::markers::{EncoderKind, EncoderVectorKind};

#[derive(Debug, PartialEq)]
pub struct CryptoEncoderVector(pub(crate) Vec<CryptoApiEncoder>);

impl AbstractEntity for CryptoEncoderVector{ type Kind = EncoderVectorKind; }
impl EncoderVectorEntity for CryptoEncoderVector{
    fn encoder_count(&self) -> EncoderCount {
        EncoderCount(self.0.len())
    }
}
