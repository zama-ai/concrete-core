macro_rules! jserr {
    ($expr: expr) => {
        $expr.map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    };
}

macro_rules! wrap {
    ($newtype: ident, $expr: expr) => {
        $expr
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map($newtype)
    };
}

mod default_engine;
pub use default_engine::*;

mod default_parallel_engine;
pub use default_parallel_engine::*;

mod default_serialization_engine;
pub use default_serialization_engine::*;
