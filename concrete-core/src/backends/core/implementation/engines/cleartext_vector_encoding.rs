use crate::backends::core::private::crypto::encoding::{Encoder, PlaintextList};
use crate::prelude::{
    CleartextVectorEncodingEngine, CleartextVectorEncodingError, CoreEngine, CryptoEncoderVector,
    FloatCleartextVector64, PlaintextVector32, PlaintextVector64,
};

impl CleartextVectorEncodingEngine<CryptoEncoderVector, FloatCleartextVector64, PlaintextVector32>
for CoreEngine
{
    fn encode_cleartext_vector(
        &mut self,
        encoder_vector: &CryptoEncoderVector,
        cleartext_vector: &FloatCleartextVector64,
    ) -> Result<PlaintextVector32, CleartextVectorEncodingError<Self::EngineError>> {
        CleartextVectorEncodingError::perform_generic_checks(encoder_vector, cleartext_vector)?;
        Ok(unsafe { self.encode_cleartext_vector_unchecked(encoder_vector, cleartext_vector) })
    }

    unsafe fn encode_cleartext_vector_unchecked(
        &mut self,
        encoder_vector: &CryptoEncoderVector,
        cleartext_vector: &FloatCleartextVector64,
    ) -> PlaintextVector32 {
        PlaintextVector32(PlaintextList::from_container(
            encoder_vector
                .0
                .iter()
                .zip(cleartext_vector.0.cleartext_iter())
                .map(|(enc, clear)| enc.encode(*clear).0)
                .collect::<Vec<_>>(),
        ))
    }
}

impl CleartextVectorEncodingEngine<CryptoEncoderVector, FloatCleartextVector64, PlaintextVector64>
for CoreEngine
{
    fn encode_cleartext_vector(
        &mut self,
        encoder_vector: &CryptoEncoderVector,
        cleartext_vector: &FloatCleartextVector64,
    ) -> Result<PlaintextVector64, CleartextVectorEncodingError<Self::EngineError>> {
        CleartextVectorEncodingError::perform_generic_checks(encoder_vector, cleartext_vector)?;
        Ok(unsafe { self.encode_cleartext_vector_unchecked(encoder_vector, cleartext_vector) })
    }

    unsafe fn encode_cleartext_vector_unchecked(
        &mut self,
        encoder_vector: &CryptoEncoderVector,
        cleartext_vector: &FloatCleartextVector64,
    ) -> PlaintextVector64 {
        PlaintextVector64(PlaintextList::from_container(
            encoder_vector
                .0
                .iter()
                .zip(cleartext_vector.0.cleartext_iter())
                .map(|(enc, clear)| enc.encode(*clear).0)
                .collect::<Vec<_>>(),
        ))
    }
}
