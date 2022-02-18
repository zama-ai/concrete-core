use crate::backends::core::private::crypto::encoding::CryptoApiEncoder;
use crate::prelude::{AbstractEntity, EncoderEntity};
use crate::prelude::markers::EncoderKind;

#[derive(Debug, PartialEq)]
pub struct CryptoEncoder(pub(crate) CryptoApiEncoder);

impl AbstractEntity for CryptoEncoder{ type Kind = EncoderKind; }
impl EncoderEntity for CryptoEncoder{}