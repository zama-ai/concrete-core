use crate::commons::crypto::lwe::LweSeededList as ImplLweSeededList;
use crate::commons::math::random::CompressionSeed;
use crate::prelude::{LweCiphertextCount, LweDimension};
use crate::specification::entities::markers::LweSeededCiphertextArrayKind;
use crate::specification::entities::{AbstractEntity, LweSeededCiphertextArrayEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an array of seeded LWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertextArray32(pub(crate) ImplLweSeededList<Vec<u32>>);

impl AbstractEntity for LweSeededCiphertextArray32 {
    type Kind = LweSeededCiphertextArrayKind;
}

impl LweSeededCiphertextArrayEntity for LweSeededCiphertextArray32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.get_compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededCiphertextArray32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array of seeded LWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertextArray64(pub(crate) ImplLweSeededList<Vec<u64>>);

impl AbstractEntity for LweSeededCiphertextArray64 {
    type Kind = LweSeededCiphertextArrayKind;
}

impl LweSeededCiphertextArrayEntity for LweSeededCiphertextArray64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.get_compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededCiphertextArray64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
