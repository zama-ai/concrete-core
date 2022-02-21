use std::panic;
use crate::entities::*;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::*;
use concrete_core::backends::core::private::crypto::encoding::CryptoApiEncoder;
use concrete_core::prelude as core;
use concrete_core::prelude::{
    AbstractEngine, CleartextCreationEngine, CleartextEncodingEngine, CleartextRetrievalEngine,
    CleartextVectorCreationEngine, CleartextVectorEncodingEngine, CleartextVectorRetrievalEngine,
    GlweCiphertextDecryptionEngine, GlweCiphertextEncryptionEngine, GlweSecretKeyCreationEngine,
    GlweToLweSecretKeyTransmutationEngine, LweBootstrapKeyCreationEngine,
    LweCiphertextDecryptionEngine, LweCiphertextEncryptionEngine,
    LweCiphertextVectorDecryptionEngine, LweCiphertextVectorEncryptionEngine,
    LweKeyswitchKeyCreationEngine, LweSecretKeyCreationEngine, PlaintextCreationEngine,
    PlaintextDecodingEngine, PlaintextRetrievalEngine, PlaintextVectorCreationEngine,
    PlaintextVectorDecodingEngine, PlaintextVectorRetrievalEngine,
};
use js_sys::{BigInt, BigUint64Array, Float64Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct CoreEngine(core::CoreEngine);

#[wasm_bindgen]
impl CoreEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<CoreEngine, JsError> {
        #[cfg(feature = "console_error_panic_hook")]
            panic::set_hook(Box::new(console_error_panic_hook::hook));

        Ok(CoreEngine(
            core::CoreEngine::new().map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_encoder(
        &mut self,
        offset: f64,
        delta: f64,
        nb_bit_precision: u32,
        nb_bit_padding: u32,
        round: bool,
    ) -> Result<CryptoEncoder, JsError> {
        Ok(CryptoEncoder(core::CryptoEncoder(CryptoApiEncoder {
            o: offset,
            delta,
            nb_bit_padding: nb_bit_padding as usize,
            nb_bit_precision: nb_bit_precision as usize,
            round,
        })))
    }

    pub fn create_encoder_vector(
        &mut self,
        offset: f64,
        delta: f64,
        nb_bit_precision: u32,
        nb_bit_padding: u32,
        round: bool,
        size: u32,
    ) -> Result<CryptoEncoderVector, JsError> {

        Ok(CryptoEncoderVector(core::CryptoEncoderVector(vec![CryptoApiEncoder {
            o: offset,
            delta,
            nb_bit_padding: nb_bit_padding as usize,
            nb_bit_precision: nb_bit_precision as usize,
            round,
        }; size as usize])))
    }

    pub fn create_plaintext_64(&mut self, input: u64) -> Result<Plaintext64, JsError> {
        Ok(Plaintext64(
            self.0
                .create_plaintext(&input)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_plaintext_vector_64(
        &mut self,
        input: &[u64],
    ) -> Result<PlaintextVector64, JsError> {
        Ok(PlaintextVector64(
            self.0
                .create_plaintext_vector(&input)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_float_cleartext_64(&mut self, input: f64) -> Result<FloatCleartext64, JsError> {
        Ok(FloatCleartext64(
            self.0
                .create_cleartext(&input)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_float_cleartext_vector_64(
        &mut self,
        input: &[f64],
    ) -> Result<FloatCleartextVector64, JsError> {
        Ok(FloatCleartextVector64(
            self.0
                .create_cleartext_vector(&input)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn retrieve_plaintext_64(&mut self, input: &Plaintext64) -> Result<u64, JsError> {
        Ok(self
            .0
            .retrieve_plaintext(&input.0)
            .map_err(|e| JsError::new(format!("{}", e).as_str()))?)
    }

    pub fn retrieve_plaintext_vector_64(
        &mut self,
        input: &PlaintextVector64,
    ) -> Result<BigUint64Array, JsError> {
        let a = self
            .0
            .retrieve_plaintext_vector(&input.0)
            .map_err(|e| JsError::new(format!("{}", e).as_str()))?
            .into_iter()
            .map(BigInt::from)
            .collect::<Vec<BigInt>>();
        Ok(a.as_slice().into())
    }

    pub fn retrieve_float_cleartext_64(
        &mut self,
        input: &FloatCleartext64,
    ) -> Result<f64, JsError> {
        Ok(self
            .0
            .retrieve_cleartext(&input.0)
            .map_err(|e| JsError::new(format!("{}", e).as_str()))?)
    }

    pub fn retrieve_float_cleartext_vector_64(
        &mut self,
        input: &FloatCleartextVector64,
    ) -> Result<Float64Array, JsError> {
        Ok(self
            .0
            .retrieve_cleartext_vector(&input.0)
            .map_err(|e| JsError::new(format!("{}", e).as_str()))?
            .as_slice()
            .into())
    }

    pub fn encode_float_cleartext_64_to_plaintext_64(
        &mut self,
        encoder: &CryptoEncoder,
        input: &FloatCleartext64,
    ) -> Result<Plaintext64, JsError> {
        Ok(Plaintext64(
            self.0
                .encode_cleartext(&encoder.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn encode_float_cleartext_vector_64_to_plaintext_vector_64(
        &mut self,
        encoder: &CryptoEncoderVector,
        input: &FloatCleartextVector64,
    ) -> Result<PlaintextVector64, JsError> {
        Ok(PlaintextVector64(
            self.0
                .encode_cleartext_vector(&encoder.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn decode_plaintext_64_to_float_cleartext_64(
        &mut self,
        encoder: &CryptoEncoder,
        input: &Plaintext64,
    ) -> Result<FloatCleartext64, JsError> {
        Ok(FloatCleartext64(
            self.0
                .decode_plaintext(&encoder.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn decode_plaintext_vector_64_to_float_cleartext_vector_64(
        &mut self,
        encoder: &CryptoEncoderVector,
        input: &PlaintextVector64,
    ) -> Result<FloatCleartextVector64, JsError> {
        Ok(FloatCleartextVector64(
            self.0
                .decode_plaintext_vector(&encoder.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_glwe_secret_key_64(
        &mut self,
        glwe_dimension: u32,
        polynomial_size: u32,
    ) -> Result<GlweSecretKey64, JsError> {
        Ok(GlweSecretKey64(
            self.0
                .create_glwe_secret_key(
                    GlweDimension(glwe_dimension as usize),
                    PolynomialSize(polynomial_size as usize),
                )
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn encrypt_glwe_ciphertext_64(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        variance: f64,
    ) -> Result<GlweCiphertext64, JsError> {
        Ok(GlweCiphertext64(
            self.0
                .encrypt_glwe_ciphertext(&key.0, &input.0, Variance(variance))
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn decrypt_glwe_ciphertext_64(
        &mut self,
        key: &GlweSecretKey64,
        input: GlweCiphertext64,
    ) -> Result<PlaintextVector64, JsError> {
        Ok(PlaintextVector64(
            self.0
                .decrypt_glwe_ciphertext(&key.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_lwe_secret_key_64(
        &mut self,
        lwe_dimension: u32,
    ) -> Result<LweSecretKey64, JsError> {
        Ok(LweSecretKey64(
            self.0
                .create_lwe_secret_key(LweDimension(lwe_dimension as usize))
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn encrypt_lwe_ciphertext_64(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        variance: f64,
    ) -> Result<LweCiphertext64, JsError> {
        Ok(LweCiphertext64(
            self.0
                .encrypt_lwe_ciphertext(&key.0, &input.0, Variance(variance))
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn decrypt_lwe_ciphertext_64(
        &mut self,
        key: &LweSecretKey64,
        input: LweCiphertext64,
    ) -> Result<Plaintext64, JsError> {
        Ok(Plaintext64(
            self.0
                .decrypt_lwe_ciphertext(&key.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn encrypt_lwe_ciphertext_vector_64(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextVector64,
        variance: f64,
    ) -> Result<LweCiphertextVector64, JsError> {
        Ok(LweCiphertextVector64(
            self.0
                .encrypt_lwe_ciphertext_vector(&key.0, &input.0, Variance(variance))
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn decrypt_lwe_ciphertext_vector_64(
        &mut self,
        key: &LweSecretKey64,
        input: LweCiphertextVector64,
    ) -> Result<PlaintextVector64, JsError> {
        Ok(PlaintextVector64(
            self.0
                .decrypt_lwe_ciphertext_vector(&key.0, &input.0)
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_keyswitch_key_64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        base_log: u32,
        level: u32,
        variance: f64,
    ) -> Result<LweKeyswitchKey64, JsError> {
        Ok(LweKeyswitchKey64(
            self.0
                .create_lwe_keyswitch_key(
                    &input_key.0,
                    &output_key.0,
                    DecompositionLevelCount(level as usize),
                    DecompositionBaseLog(base_log as usize),
                    Variance(variance),
                )
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn create_bootstrap_key_64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        base_log: u32,
        level: u32,
        variance: f64,
    ) -> Result<LweBootstrapKey64, JsError> {
        Ok(LweBootstrapKey64(
            self.0
                .create_lwe_bootstrap_key(
                    &input_key.0,
                    &output_key.0,
                    DecompositionBaseLog(base_log as usize),
                    DecompositionLevelCount(level as usize),
                    Variance(variance),
                )
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }

    pub fn convert_glwe_secret_key_64_to_lwe_secret_key_64(
        &mut self,
        input_key: &GlweSecretKey64,
    ) -> Result<LweSecretKey64, JsError> {
        Ok(LweSecretKey64(
            self.0
                .transmute_glwe_secret_key_to_lwe_secret_key(input_key.0.to_owned())
                .map_err(|e| JsError::new(format!("{}", e).as_str()))?,
        ))
    }
}
