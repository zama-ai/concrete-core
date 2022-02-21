use crate::backends::core::private::crypto::encoding::{CleartextList, Encoder};
use crate::prelude::{
    CoreEngine, CryptoEncoderVector, FloatCleartextVector64, PlaintextVector32,
    PlaintextVector64, PlaintextVectorDecodingEngine, PlaintextVectorDecodingError,
};

impl PlaintextVectorDecodingEngine<CryptoEncoderVector, PlaintextVector32, FloatCleartextVector64>
    for CoreEngine
{
    fn decode_plaintext_vector(
        &mut self,
        encoder: &CryptoEncoderVector,
        input: &PlaintextVector32,
    ) -> Result<FloatCleartextVector64, PlaintextVectorDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_vector_unchecked(encoder, input) })
    }

    unsafe fn decode_plaintext_vector_unchecked(
        &mut self,
        encoder: &CryptoEncoderVector,
        input: &PlaintextVector32,
    ) -> FloatCleartextVector64 {
        FloatCleartextVector64(CleartextList::from_container(
            encoder
                .0
                .iter()
                .zip(input.0.plaintext_iter())
                .map(|(enc, p)| enc.decode(*p).0)
                .collect::<Vec<_>>(),
        ))
    }
}

impl PlaintextVectorDecodingEngine<CryptoEncoderVector, PlaintextVector64, FloatCleartextVector64>
    for CoreEngine
{
    fn decode_plaintext_vector(
        &mut self,
        encoder: &CryptoEncoderVector,
        input: &PlaintextVector64,
    ) -> Result<FloatCleartextVector64, PlaintextVectorDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_vector_unchecked(encoder, input) })
    }

    unsafe fn decode_plaintext_vector_unchecked(
        &mut self,
        encoder: &CryptoEncoderVector,
        input: &PlaintextVector64,
    ) -> FloatCleartextVector64 {
        FloatCleartextVector64(CleartextList::from_container(
            encoder
                .0
                .iter()
                .zip(input.0.plaintext_iter())
                .map(|(enc, p)| enc.decode(*p).0)
                .collect::<Vec<_>>(),
        ))
    }
}
