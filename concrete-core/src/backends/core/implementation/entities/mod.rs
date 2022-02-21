//! A module containing all the [entities](crate::specification::entities) exposed by the core
//! backend.

mod encoder;
mod encoder_vector;
mod cleartext;
mod cleartext_vector;
mod ggsw_ciphertext;
mod glwe_ciphertext;
mod glwe_ciphertext_vector;
mod glwe_secret_key;
mod gsw_ciphertext;
mod lwe_bootstrap_key;
mod lwe_ciphertext;
mod lwe_ciphertext_vector;
mod lwe_keyswitch_key;
mod lwe_secret_key;
mod plaintext;
mod plaintext_vector;

pub use encoder::*;
pub use encoder_vector::*;
pub use cleartext::*;
pub use cleartext_vector::*;
pub use ggsw_ciphertext::*;
pub use glwe_ciphertext::*;
pub use glwe_ciphertext_vector::*;
pub use glwe_secret_key::*;
pub use gsw_ciphertext::*;
pub use lwe_bootstrap_key::*;
pub use lwe_ciphertext::*;
pub use lwe_ciphertext_vector::*;
pub use lwe_keyswitch_key::*;
pub use lwe_secret_key::*;
pub use plaintext::*;
pub use plaintext_vector::*;

macro_rules! base64_impl {
    ($($struct:ident,)+) => {
        $(
        impl $struct {
            pub fn from_base64(input: &str) -> Option<Self> {
                let bytes = base64::decode(input).ok()?;
                bincode::deserialize(&bytes).ok()
            }
            pub fn as_base64(&self) -> Option<String>{
                let bytes = bincode::serialize(self).ok()?;
                Some(base64::encode(bytes))
            }
        }
        )+
    };
}

base64_impl! {
    Cleartext32,
    Cleartext64,
    CleartextVector32,
    CleartextVector64,
    FloatCleartext64,
    FloatCleartextVector64,
    Plaintext32,
    Plaintext64,
    PlaintextVector32,
    PlaintextVector64,
    CryptoEncoder,
    CryptoEncoderVector,
    GgswCiphertext32,
    GgswCiphertext64,
    GswCiphertext32,
    GswCiphertext64,
    GlweCiphertext32,
    GlweCiphertext64,
    GlweCiphertextVector32,
    GlweCiphertextVector64,
    GlweSecretKey32,
    GlweSecretKey64,
    LweCiphertext32,
    LweCiphertext64,
    LweCiphertextVector32,
    LweCiphertextVector64,
    LweSecretKey32,
    LweSecretKey64,
    LweKeyswitchKey32,
    LweKeyswitchKey64,
    LweBootstrapKey32,
    LweBootstrapKey64,
 }