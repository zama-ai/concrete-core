use wasm_bindgen::prelude::*;

macro_rules! reexp_entities {
    ($(($struct:ident, $default_struct:ident),)+) => {
        $(

        #[wasm_bindgen]
        pub struct $struct(pub(crate) concrete_core::prelude::$default_struct);

        )+
    };
}

reexp_entities! {
    (FloatEncoder, FloatEncoder),
    (FloatEncoderArray, FloatEncoderArray),
    (CleartextF64, CleartextF64),
    (CleartextArrayF64, CleartextArrayF64),
    (Cleartext64, Cleartext64),
    (CleartextArray64, CleartextArray64),
    (Plaintext64, Plaintext64),
    (PlaintextArray64, PlaintextArray64),
    (LweCiphertext64, LweCiphertext64),
    (LweCiphertextArray64, LweCiphertextArray64),
    (LweSecretKey64, LweSecretKey64),
    (LweKeyswitchKey64, LweKeyswitchKey64),
    (LweBootstrapKey64, LweBootstrapKey64),
    (GlweCiphertext64, GlweCiphertext64),
    (GlweCiphertextArray64, GlweCiphertextArray64),
    (GlweSecretKey64, GlweSecretKey64),
    (Cleartext32, Cleartext32),
    (CleartextArray32, CleartextArray32),
    (Plaintext32, Plaintext32),
    (PlaintextArray32, PlaintextArray32),
    (LweCiphertext32, LweCiphertext32),
    (LweCiphertextArray32, LweCiphertextArray32),
    (LweSecretKey32, LweSecretKey32),
    (LweKeyswitchKey32, LweKeyswitchKey32),
    (LweBootstrapKey32, LweBootstrapKey32),
    (GlweCiphertext32, GlweCiphertext32),
    (GlweCiphertextArray32, GlweCiphertextArray32),
    (GlweSecretKey32, GlweSecretKey32),
}
