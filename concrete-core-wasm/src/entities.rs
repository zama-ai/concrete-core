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
    (FloatEncoderVector, FloatEncoderVector),
    (CleartextF64, CleartextF64),
    (CleartextVectorF64, CleartextVectorF64),
    (Cleartext64, Cleartext64),
    (CleartextVector64, CleartextVector64),
    (Plaintext64, Plaintext64),
    (PlaintextVector64, PlaintextVector64),
    (LweCiphertext64, LweCiphertext64),
    (LweCiphertextVector64, LweCiphertextVector64),
    (LweSecretKey64, LweSecretKey64),
    (LweKeyswitchKey64, LweKeyswitchKey64),
    (LweBootstrapKey64, LweBootstrapKey64),
    (GlweCiphertext64, GlweCiphertext64),
    (GlweCiphertextVector64, GlweCiphertextVector64),
    (GlweSecretKey64, GlweSecretKey64),
    (Cleartext32, Cleartext32),
    (CleartextVector32, CleartextVector32),
    (Plaintext32, Plaintext32),
    (PlaintextVector32, PlaintextVector32),
    (LweCiphertext32, LweCiphertext32),
    (LweCiphertextVector32, LweCiphertextVector32),
    (LweSecretKey32, LweSecretKey32),
    (LweKeyswitchKey32, LweKeyswitchKey32),
    (LweBootstrapKey32, LweBootstrapKey32),
    (GlweCiphertext32, GlweCiphertext32),
    (GlweCiphertextVector32, GlweCiphertextVector32),
    (GlweSecretKey32, GlweSecretKey32),
}
