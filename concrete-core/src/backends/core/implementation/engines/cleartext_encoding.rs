use crate::backends::core::private::crypto::encoding::Encoder;
use crate::prelude::{CleartextEncodingEngine, CleartextEncodingError, CoreEngine, CryptoEncoder, FloatCleartext64, Plaintext32, Plaintext64};

impl CleartextEncodingEngine<CryptoEncoder, FloatCleartext64, Plaintext32> for CoreEngine{
    fn encode_cleartext(&mut self, encoder: &CryptoEncoder, cleartext: &FloatCleartext64) -> Result<Plaintext32, CleartextEncodingError<Self::EngineError>> {
        Ok(unsafe{self.encode_cleartext_unchecked(encoder, cleartext)})
    }

    unsafe fn encode_cleartext_unchecked(&mut self, encoder: &CryptoEncoder, cleartext: &FloatCleartext64) -> Plaintext32 {
        Plaintext32(encoder.0.encode(cleartext.0))
    }
}

impl CleartextEncodingEngine<CryptoEncoder, FloatCleartext64, Plaintext64> for CoreEngine{
    fn encode_cleartext(&mut self, encoder: &CryptoEncoder, cleartext: &FloatCleartext64) -> Result<Plaintext64, CleartextEncodingError<Self::EngineError>> {
        Ok(unsafe{self.encode_cleartext_unchecked(encoder, cleartext)})
    }

    unsafe fn encode_cleartext_unchecked(&mut self, encoder: &CryptoEncoder, cleartext: &FloatCleartext64) -> Plaintext64 {
        Plaintext64(encoder.0.encode(cleartext.0))
    }
}
