use concrete_core::commons::math::random::Seed;
use concrete_core::prelude::Seeder;
use js_sys::{Function, Uint8Array};
use std::panic;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

const SEED_BYTES_COUNT: usize = 16;

#[wasm_bindgen]
pub struct JsFunctionSeeder(Function);

#[wasm_bindgen]
impl JsFunctionSeeder {
    #[wasm_bindgen(constructor)]
    pub fn new(func: Function) -> JsFunctionSeeder {
        panic::set_hook(Box::new(console_error_panic_hook::hook));
        JsFunctionSeeder(func)
    }
}

impl Seeder for JsFunctionSeeder {
    fn seed(&mut self) -> Seed {
        let output = self.0.call0(&JsValue::NULL).unwrap();
        let array = Uint8Array::new(&output);
        if array.length() as usize != SEED_BYTES_COUNT {
            panic!("The seeder function must return a Uint8Array of size 16.");
        }
        let mut bytes = [0u8; SEED_BYTES_COUNT];
        array.copy_to(&mut bytes);
        let seed = u128::from_ne_bytes(bytes);
        Seed(seed)
    }

    fn is_available() -> bool
    where
        Self: Sized,
    {
        true
    }
}
