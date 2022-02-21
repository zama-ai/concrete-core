use crate::backends::core::private::crypto::encoding::CryptoApiEncoder;
use crate::prelude::{AbstractEntity, EncoderEntity};
use crate::prelude::markers::EncoderKind;
use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CryptoEncoder(pub CryptoApiEncoder);

impl AbstractEntity for CryptoEncoder { type Kind = EncoderKind; }

impl EncoderEntity for CryptoEncoder {}