use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{
    FourierGgswCiphertext32, FourierGgswCiphertext64, GgswCiphertext32, GgswCiphertext64,
};

/// A trait implemented by ggsw ciphertext prototypes.
pub trait GgswCiphertextPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary ggsw ciphertext entity.
pub struct ProtoBinaryGgswCiphertext32(pub(crate) GgswCiphertext32);
impl GgswCiphertextPrototype for ProtoBinaryGgswCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary ggsw ciphertext entity.
pub struct ProtoBinaryGgswCiphertext64(pub(crate) GgswCiphertext64);
impl GgswCiphertextPrototype for ProtoBinaryGgswCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}

/// A type representing the prototype of a 32 bit binary ggsw ciphertext entity
/// in the Fourier domain.
pub struct ProtoBinaryFourierGgswCiphertext32(pub(crate) FourierGgswCiphertext32);
impl GgswCiphertextPrototype for ProtoBinaryFourierGgswCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary ggsw ciphertext entity
/// in the Fourier domain.
pub struct ProtoBinaryFourierGgswCiphertext64(pub(crate) FourierGgswCiphertext64);
impl GgswCiphertextPrototype for ProtoBinaryFourierGgswCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}