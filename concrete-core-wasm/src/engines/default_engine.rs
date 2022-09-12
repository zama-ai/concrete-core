use crate::*;
use concrete_core::prelude as core;
use concrete_core::prelude::{
    AbstractEngine, FloatEncoderCenterRadiusConfig, FloatEncoderMinMaxConfig,
};
use concrete_core::specification::engines::*;
use serde::Deserialize;
use std::panic;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DefaultEngine(core::DefaultEngine);

#[wasm_bindgen]
impl DefaultEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(seeder: crate::JsFunctionSeeder) -> JsResult<DefaultEngine> {
        panic::set_hook(Box::new(console_error_panic_hook::hook));
        wrap!(DefaultEngine, core::DefaultEngine::new(Box::new(seeder)))
    }

    pub fn create_plaintext_64(&mut self, input: u64) -> JsResult<Plaintext64> {
        wrap!(Plaintext64, self.0.create_plaintext_from(&input))
    }

    pub fn create_plaintext_array_64(&mut self, input: Vec<u64>) -> JsResult<PlaintextArray64> {
        wrap!(PlaintextArray64, self.0.create_plaintext_array_from(&input))
    }

    pub fn retrieve_plaintext_64(&mut self, input: &Plaintext64) -> JsResult<u64> {
        jserr!(self.0.retrieve_plaintext(&input.0))
    }

    pub fn retrieve_plaintext_array_64(&mut self, input: &PlaintextArray64) -> JsResult<Vec<u64>> {
        jserr!(self.0.retrieve_plaintext_array(&input.0))
    }

    pub fn create_plaintext_32(&mut self, input: u32) -> JsResult<Plaintext32> {
        wrap!(Plaintext32, self.0.create_plaintext_from(&input))
    }

    pub fn create_plaintext_array_32(&mut self, input: Vec<u32>) -> JsResult<PlaintextArray32> {
        wrap!(PlaintextArray32, self.0.create_plaintext_array_from(&input))
    }

    pub fn retrieve_plaintext_32(&mut self, input: &Plaintext32) -> JsResult<u32> {
        jserr!(self.0.retrieve_plaintext(&input.0))
    }

    pub fn retrieve_plaintext_array_32(&mut self, input: &PlaintextArray32) -> JsResult<Vec<u32>> {
        jserr!(self.0.retrieve_plaintext_array(&input.0))
    }

    pub fn create_cleartext_f64(&mut self, input: f64) -> JsResult<CleartextF64> {
        wrap!(CleartextF64, self.0.create_cleartext_from(&input))
    }

    pub fn create_cleartext_array_f64(&mut self, input: Vec<f64>) -> JsResult<CleartextArrayF64> {
        wrap!(
            CleartextArrayF64,
            self.0.create_cleartext_array_from(input.as_slice())
        )
    }

    pub fn retrieve_cleartext_f64(&mut self, cleartext: &CleartextF64) -> JsResult<f64> {
        jserr!(self.0.retrieve_cleartext(&cleartext.0))
    }

    pub fn retrieve_cleartext_array_f64(
        &mut self,
        input: &CleartextArrayF64,
    ) -> JsResult<Vec<f64>> {
        jserr!(self.0.retrieve_cleartext_array(&input.0))
    }

    pub fn create_encoder_f64_min_max(&mut self, config: &JsValue) -> JsResult<FloatEncoder> {
        #[derive(Deserialize)]
        struct Config {
            min: f64,
            max: f64,
            nb_bit_precision: usize,
            nb_bit_padding: usize,
        }
        let config: Config = config.into_serde().expect(
            "\
            The provided encoder configuration does not follow the expected format. 
            Please provide an object which contains the following fields:
                + min: f64
                + max: f64,
                + nb_bit_precision: u32,
                + nb_bit_padding: u32
        ",
        );

        wrap!(
            FloatEncoder,
            self.0.create_encoder_from(&FloatEncoderMinMaxConfig {
                min: config.min,
                max: config.max,
                nb_bit_padding: config.nb_bit_padding,
                nb_bit_precision: config.nb_bit_precision
            })
        )
    }

    pub fn create_encoder_f64_center_radius(&mut self, config: &JsValue) -> JsResult<FloatEncoder> {
        #[derive(Deserialize)]
        struct Config {
            center: f64,
            radius: f64,
            nb_bit_precision: usize,
            nb_bit_padding: usize,
        }
        let config: Config = config.into_serde().expect(
            "\
            The provided encoder configuration does not follow the expected format. 
            Please provide an object which contains the following fields:
                + center: f64
                + radius: f64,
                + nb_bit_precision: u32,
                + nb_bit_padding: u32
        ",
        );

        wrap!(
            FloatEncoder,
            self.0.create_encoder_from(&FloatEncoderCenterRadiusConfig {
                center: config.center,
                radius: config.radius,
                nb_bit_padding: config.nb_bit_padding,
                nb_bit_precision: config.nb_bit_precision
            })
        )
    }

    #[allow(clippy::boxed_local)]
    pub fn create_encoder_array_f64_min_max(
        &mut self,
        config: Box<[JsValue]>,
    ) -> JsResult<FloatEncoderArray> {
        #[derive(Deserialize)]
        struct Config {
            min: f64,
            max: f64,
            nb_bit_precision: usize,
            nb_bit_padding: usize,
        }
        let configs: Vec<FloatEncoderMinMaxConfig> = config
            .iter()
            .map(|config| {
                let config: Config = config.into_serde().expect(
                    "\
                    The provided encoder configuration does not follow the expected format. 
                    Please provide an object which contains the following fields:
                        + min: f64
                        + max: f64,
                        + nb_bit_precision: u32,
                        + nb_bit_padding: u32
                    ",
                );
                FloatEncoderMinMaxConfig {
                    min: config.min,
                    max: config.max,
                    nb_bit_padding: config.nb_bit_padding,
                    nb_bit_precision: config.nb_bit_precision,
                }
            })
            .collect();
        wrap!(
            FloatEncoderArray,
            self.0.create_encoder_array_from(configs.as_slice())
        )
    }

    #[allow(clippy::boxed_local)]
    pub fn create_encoder_array_f64_center_radius(
        &mut self,
        config: Box<[JsValue]>,
    ) -> JsResult<FloatEncoderArray> {
        #[derive(Deserialize)]
        struct Config {
            center: f64,
            radius: f64,
            nb_bit_precision: usize,
            nb_bit_padding: usize,
        }
        let configs: Vec<FloatEncoderCenterRadiusConfig> = config
            .iter()
            .map(|config| {
                let config: Config = config.into_serde().expect(
                    "\
                    The provided encoder configuration does not follow the expected format. 
                    Please provide an object which contains the following fields:
                        + center: f64
                        + radius: f64,
                        + nb_bit_precision: u32,
                        + nb_bit_padding: u32
                    ",
                );
                FloatEncoderCenterRadiusConfig {
                    center: config.center,
                    radius: config.radius,
                    nb_bit_padding: config.nb_bit_padding,
                    nb_bit_precision: config.nb_bit_precision,
                }
            })
            .collect();
        wrap!(
            FloatEncoderArray,
            self.0.create_encoder_array_from(configs.as_slice())
        )
    }

    pub fn encode_cleartext_f64_plaintext_32(
        &mut self,
        encoder: &FloatEncoder,
        cleartext: &CleartextF64,
    ) -> JsResult<Plaintext32> {
        wrap!(
            Plaintext32,
            self.0.encode_cleartext(&encoder.0, &cleartext.0)
        )
    }

    pub fn encode_cleartext_f64_plaintext_64(
        &mut self,
        encoder: &FloatEncoder,
        cleartext: &CleartextF64,
    ) -> JsResult<Plaintext64> {
        wrap!(
            Plaintext64,
            self.0.encode_cleartext(&encoder.0, &cleartext.0)
        )
    }

    pub fn encode_cleartext_array_f64_plaintext_array_32(
        &mut self,
        encoder_array: &FloatEncoderArray,
        cleartext_array: &CleartextArrayF64,
    ) -> JsResult<PlaintextArray32> {
        wrap!(
            PlaintextArray32,
            self.0
                .encode_cleartext_array(&encoder_array.0, &cleartext_array.0)
        )
    }

    pub fn encode_cleartext_array_f64_plaintext_array_64(
        &mut self,
        encoder_array: &FloatEncoderArray,
        cleartext_array: &CleartextArrayF64,
    ) -> JsResult<PlaintextArray64> {
        wrap!(
            PlaintextArray64,
            self.0
                .encode_cleartext_array(&encoder_array.0, &cleartext_array.0)
        )
    }

    pub fn decode_plaintext_32_cleartext_f64(
        &mut self,
        encoder: &FloatEncoder,
        plaintext: &Plaintext32,
    ) -> JsResult<CleartextF64> {
        wrap!(
            CleartextF64,
            self.0.decode_plaintext(&encoder.0, &plaintext.0)
        )
    }

    pub fn decode_plaintext_64_cleartext_f64(
        &mut self,
        encoder: &FloatEncoder,
        plaintext: &Plaintext64,
    ) -> JsResult<CleartextF64> {
        wrap!(
            CleartextF64,
            self.0.decode_plaintext(&encoder.0, &plaintext.0)
        )
    }

    pub fn decode_plaintext_array_32_cleartext_array_f64(
        &mut self,
        encoder_array: &FloatEncoderArray,
        plaintext_array: &PlaintextArray32,
    ) -> JsResult<CleartextArrayF64> {
        wrap!(
            CleartextArrayF64,
            self.0
                .decode_plaintext_array(&encoder_array.0, &plaintext_array.0)
        )
    }

    pub fn decode_plaintext_array_64_cleartext_array_f64(
        &mut self,
        encoder_array: &FloatEncoderArray,
        plaintext_array: &PlaintextArray64,
    ) -> JsResult<CleartextArrayF64> {
        wrap!(
            CleartextArrayF64,
            self.0
                .decode_plaintext_array(&encoder_array.0, &plaintext_array.0)
        )
    }

    pub fn create_lwe_secret_key_32(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> JsResult<LweSecretKey32> {
        wrap!(
            LweSecretKey32,
            self.0.generate_new_lwe_secret_key(lwe_dimension.0)
        )
    }

    pub fn create_lwe_secret_key_64(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> JsResult<LweSecretKey64> {
        wrap!(
            LweSecretKey64,
            self.0.generate_new_lwe_secret_key(lwe_dimension.0)
        )
    }

    pub fn create_glwe_secret_key_32(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
    ) -> JsResult<GlweSecretKey32> {
        wrap!(
            GlweSecretKey32,
            self.0
                .generate_new_glwe_secret_key(glwe_dimension.0, poly_size.0)
        )
    }

    pub fn create_glwe_secret_key_64(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
    ) -> JsResult<GlweSecretKey64> {
        wrap!(
            GlweSecretKey64,
            self.0
                .generate_new_glwe_secret_key(glwe_dimension.0, poly_size.0)
        )
    }

    pub fn create_lwe_bootstrap_key_32(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> JsResult<LweBootstrapKey32> {
        wrap!(
            LweBootstrapKey32,
            self.0.generate_new_lwe_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0
            )
        )
    }

    pub fn create_lwe_bootstrap_key_64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> JsResult<LweBootstrapKey64> {
        wrap!(
            LweBootstrapKey64,
            self.0.generate_new_lwe_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0
            )
        )
    }

    pub fn encrypt_lwe_ciphertext_32(
        &mut self,
        key: &LweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
    ) -> JsResult<LweCiphertext32> {
        wrap!(
            LweCiphertext32,
            self.0.encrypt_lwe_ciphertext(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_lwe_ciphertext_64(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> JsResult<LweCiphertext64> {
        wrap!(
            LweCiphertext64,
            self.0.encrypt_lwe_ciphertext(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_lwe_ciphertext_array_32(
        &mut self,
        key: &LweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> JsResult<LweCiphertextArray32> {
        wrap!(
            LweCiphertextArray32,
            self.0
                .encrypt_lwe_ciphertext_array(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_lwe_ciphertext_array_64(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> JsResult<LweCiphertextArray64> {
        wrap!(
            LweCiphertextArray64,
            self.0
                .encrypt_lwe_ciphertext_array(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_glwe_ciphertext_32(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> JsResult<GlweCiphertext32> {
        wrap!(
            GlweCiphertext32,
            self.0.encrypt_glwe_ciphertext(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_glwe_ciphertext_64(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> JsResult<GlweCiphertext64> {
        wrap!(
            GlweCiphertext64,
            self.0.encrypt_glwe_ciphertext(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_glwe_ciphertext_array_32(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> JsResult<GlweCiphertextArray32> {
        wrap!(
            GlweCiphertextArray32,
            self.0
                .encrypt_glwe_ciphertext_array(&key.0, &input.0, noise.0)
        )
    }

    pub fn encrypt_glwe_ciphertext_array_64(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> JsResult<GlweCiphertextArray64> {
        wrap!(
            GlweCiphertextArray64,
            self.0
                .encrypt_glwe_ciphertext_array(&key.0, &input.0, noise.0)
        )
    }

    pub fn decrypt_lwe_ciphertext_32(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertext32,
    ) -> JsResult<Plaintext32> {
        wrap!(Plaintext32, self.0.decrypt_lwe_ciphertext(&key.0, &input.0))
    }

    pub fn decrypt_lwe_ciphertext_64(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertext64,
    ) -> JsResult<Plaintext64> {
        wrap!(Plaintext64, self.0.decrypt_lwe_ciphertext(&key.0, &input.0))
    }

    pub fn decrypt_lwe_ciphertext_array_32(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextArray32,
    ) -> JsResult<PlaintextArray32> {
        wrap!(
            PlaintextArray32,
            self.0.decrypt_lwe_ciphertext_array(&key.0, &input.0)
        )
    }

    pub fn decrypt_lwe_ciphertext_array_64(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextArray64,
    ) -> JsResult<PlaintextArray64> {
        wrap!(
            PlaintextArray64,
            self.0.decrypt_lwe_ciphertext_array(&key.0, &input.0)
        )
    }

    pub fn decrypt_glwe_ciphertext_32(
        &mut self,
        key: &GlweSecretKey32,
        input: &GlweCiphertext32,
    ) -> JsResult<PlaintextArray32> {
        wrap!(
            PlaintextArray32,
            self.0.decrypt_glwe_ciphertext(&key.0, &input.0)
        )
    }

    pub fn decrypt_glwe_ciphertext_64(
        &mut self,
        key: &GlweSecretKey64,
        input: &GlweCiphertext64,
    ) -> JsResult<PlaintextArray64> {
        wrap!(
            PlaintextArray64,
            self.0.decrypt_glwe_ciphertext(&key.0, &input.0)
        )
    }

    pub fn decrypt_glwe_ciphertext_array_32(
        &mut self,
        key: &GlweSecretKey32,
        input: &GlweCiphertextArray32,
    ) -> JsResult<PlaintextArray32> {
        wrap!(
            PlaintextArray32,
            self.0.decrypt_glwe_ciphertext_array(&key.0, &input.0)
        )
    }

    pub fn decrypt_glwe_ciphertext_array_64(
        &mut self,
        key: &GlweSecretKey64,
        input: &GlweCiphertextArray64,
    ) -> JsResult<PlaintextArray64> {
        wrap!(
            PlaintextArray64,
            self.0.decrypt_glwe_ciphertext_array(&key.0, &input.0)
        )
    }
}
