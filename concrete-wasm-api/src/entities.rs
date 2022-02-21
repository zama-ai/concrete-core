use wasm_bindgen::prelude::*;
use concrete_core::prelude as core;

macro_rules! reexp_entities {
    ($(($struct:ident, $core_struct:ident),)+) => {
        $(

        #[wasm_bindgen]
        pub struct $struct(pub(crate) core::$core_struct);

        #[wasm_bindgen]
        impl $struct{
            pub fn from_base64(input: &str) -> Option<$struct> {
                core::$core_struct::from_base64(input).map($struct)
            }
            pub fn as_base64(&self) -> Option<String>{
                self.0.as_base64()
            }
        }
)+
    };
}

reexp_entities! {
    (CryptoEncoder, CryptoEncoder),
    (CryptoEncoderVector, CryptoEncoderVector),
    (Cleartext64, Cleartext64),
    (CleartextVector64, CleartextVector64),
    (FloatCleartext64, FloatCleartext64),
    (FloatCleartextVector64, FloatCleartextVector64),
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
    (GgswCiphertext64, GgswCiphertext64),
    (GswCiphertext64, GswCiphertext64),
}
