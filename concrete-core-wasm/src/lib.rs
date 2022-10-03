#![allow(clippy::boxed_local)]
use concrete_core::specification::engines::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

include!(concat!(env!("OUT_DIR"), "/__gen.rs"));

mod seeder {
    use concrete_core::commons::math::random::Seed;
    use concrete_core::prelude::Seeder;
    use js_sys::{Function, Uint8Array};
    use std::panic;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsValue;

    const SEED_BYTES_COUNT: usize = 16;

    #[wasm_bindgen]
    pub struct JsFunctionSeeder {
        js_func: Function,
        buffer: [u8; SEED_BYTES_COUNT],
    }

    #[wasm_bindgen]
    impl JsFunctionSeeder {
        #[wasm_bindgen(constructor)]
        pub fn new(js_func: Function) -> JsFunctionSeeder {
            panic::set_hook(Box::new(console_error_panic_hook::hook));
            let buffer = [0u8; SEED_BYTES_COUNT];
            JsFunctionSeeder { js_func, buffer }
        }
    }

    impl Seeder for JsFunctionSeeder {
        fn seed(&mut self) -> Seed {
            let output = self.js_func.call0(&JsValue::NULL).unwrap();
            let array = Uint8Array::new(&output);
            if array.length() as usize != SEED_BYTES_COUNT {
                panic!("The seeder function must return a Uint8Array of size 16.");
            }
            array.copy_to(&mut self.buffer);
            let seed = u128::from_le_bytes(self.buffer);
            Seed(seed)
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }
    }
}
pub use seeder::*;

mod commons {
    use wasm_bindgen::prelude::*;

    macro_rules! param {
    ($(($public: ident, $private: ident, $typ: ty)),*) => {
        $(
            #[wasm_bindgen]
            pub struct $public(pub(crate) concrete_core::prelude::$private);

            #[wasm_bindgen]
            impl $public {
                #[wasm_bindgen(constructor)]
                pub fn new(val: $typ) -> $public {
                    $public(concrete_core::prelude::$private(val))
                }
            }
        )*
    };
}

    param! {
        (Variance, Variance, f64),
        (DecompositionBaseLog, DecompositionBaseLog, usize),
        (DecompositionLevelCount, DecompositionLevelCount, usize),
        (LweDimension, LweDimension, usize),
        (LweCiphertextCount, LweCiphertextCount, usize),
        (LweSize, LweSize, usize),
        (MonomialIndex, MonomialIndex, usize),
        (GlweDimension, GlweDimension, usize),
        (GlweSize, GlweSize, usize),
        (GlweCiphertextCount, GlweCiphertextCount, usize),
        (PolynomialSize, PolynomialSize, usize),
        (DeltaLog, DeltaLog, usize),
        (ExtractedBitsCount, ExtractedBitsCount, usize)
    }
}
pub use commons::*;
