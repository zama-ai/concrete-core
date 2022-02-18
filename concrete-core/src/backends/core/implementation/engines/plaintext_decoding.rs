use crate::backends::core::private::crypto::encoding::Encoder;
use crate::prelude::{CoreEngine, CryptoEncoder, FloatCleartext64, Plaintext32, Plaintext64, PlaintextDecodingEngine, PlaintextDecodingError};

impl PlaintextDecodingEngine<CryptoEncoder, Plaintext32, FloatCleartext64> for CoreEngine {
    fn decode_plaintext(&mut self, encoder: &CryptoEncoder, input: &Plaintext32) -> Result<FloatCleartext64, PlaintextDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_unchecked(input, encoder) })
    }

    unsafe fn decode_plaintext_unchecked(&mut self, input: &Plaintext32, encoder: &CryptoEncoder) -> FloatCleartext64 {
        FloatCleartext64(encoder.0.decode(input.0))
    }
}

impl PlaintextDecodingEngine<CryptoEncoder, Plaintext64, FloatCleartext64> for CoreEngine {
    fn decode_plaintext(&mut self, encoder: &CryptoEncoder, input: &Plaintext64) -> Result<FloatCleartext64, PlaintextDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_unchecked(input, encoder) })
    }

    unsafe fn decode_plaintext_unchecked(&mut self, input: &Plaintext64, encoder: &CryptoEncoder) -> FloatCleartext64 {
        FloatCleartext64(encoder.0.decode(input.0))
    }
}
