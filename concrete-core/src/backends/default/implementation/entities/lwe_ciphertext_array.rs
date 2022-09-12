use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::prelude::{LweCiphertextCount, LweDimension};
use crate::specification::entities::markers::LweCiphertextArrayKind;
use crate::specification::entities::{AbstractEntity, LweCiphertextArrayEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an array of LWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextArray32(pub(crate) ImplLweList<Vec<u32>>);

impl AbstractEntity for LweCiphertextArray32 {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for LweCiphertextArray32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCiphertextArray32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array of LWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextArray64(pub(crate) ImplLweList<Vec<u64>>);

impl AbstractEntity for LweCiphertextArray64 {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for LweCiphertextArray64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCiphertextArray64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

// LweCiphertextArrayViews are just LweCiphertextArray entities that do not own their memory,
// they use a slice as a container as opposed to Vec for the standard LweCiphertextArray

/// A structure representing an array of LWE ciphertext views, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextArrayView32<'a>(pub(crate) ImplLweList<&'a [u32]>);

impl AbstractEntity for LweCiphertextArrayView32<'_> {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for LweCiphertextArrayView32<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A structure representing an array of LWE ciphertext views, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextArrayMutView32<'a>(pub(crate) ImplLweList<&'a mut [u32]>);

impl AbstractEntity for LweCiphertextArrayMutView32<'_> {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for LweCiphertextArrayMutView32<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A structure representing an array of LWE ciphertext views, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextArrayView64<'a>(pub(crate) ImplLweList<&'a [u64]>);

impl AbstractEntity for LweCiphertextArrayView64<'_> {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for LweCiphertextArrayView64<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A structure representing an array of LWE ciphertext views, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextArrayMutView64<'a>(pub(crate) ImplLweList<&'a mut [u64]>);

impl AbstractEntity for LweCiphertextArrayMutView64<'_> {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for LweCiphertextArrayMutView64<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}
