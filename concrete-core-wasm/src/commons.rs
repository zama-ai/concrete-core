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
    (GlweDimension, GlweDimension, usize),
    (PolynomialSize, PolynomialSize, usize)
}
