use crate::*;
use concrete_core::prelude as core;
use concrete_core::prelude::AbstractEngine;
use concrete_core::specification::engines::*;
use std::panic;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DefaultParallelEngine(core::DefaultParallelEngine);

#[wasm_bindgen]
impl DefaultParallelEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(seeder: crate::JsFunctionSeeder) -> JsResult<DefaultParallelEngine> {
        panic::set_hook(Box::new(console_error_panic_hook::hook));
        wrap!(
            DefaultParallelEngine,
            core::DefaultParallelEngine::new(Box::new(seeder))
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
            self.0.create_lwe_bootstrap_key(
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
            self.0.create_lwe_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0
            )
        )
    }
}
