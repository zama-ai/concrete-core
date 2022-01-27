use crate::specification::entities::markers::{KeyDistributionMarker, LweCiphertextKind};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::LweDimension;

/// A trait implemented by types embodying an LWE ciphertext.
///
/// An LWE ciphertext is associated with a
/// [`KeyDistribution`](`LweCiphertextEntity::KeyDistribution`) type, which conveys the distribution
/// of the secret key it was encrypted with.
///
/// # Formal Definition
///
/// ## LWE Ciphertext
///
/// An LWE ciphertext is an encryption of a plaintext.
/// It is secure under the hardness assumption called Learning With Errors (LWE).
/// It is a specialization of
/// [`GLWE ciphertext`](`crate::specification::entities::GlweCiphertextEntity`).
///
/// We indicate an LWE ciphertext of a plaintext $\mathsf{pt} \in\mathbb{Z}\_q$ as the following
/// couple: $$\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt}
/// )\subseteq \mathbb{Z}\_q^{(n+1)}$$ We call $q$ the ciphertext modulus and $n$ the LWE dimension.
///
/// ## LWE dimension
/// It corresponds to the number of element in the LWE secret key.
/// In an LWE ciphertext, it is the length of the vector $\vec{a}$.
/// At [`encryption`](`crate::specification::engines::LweCiphertextEncryptionEngine`) time, it is
/// the number of uniformly random
/// integers generated.
pub trait LweCiphertextEntity: AbstractEntity<Kind = LweCiphertextKind> {
    /// The distribution of the key the ciphertext was encrypted with.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the LWE dimension of the ciphertext.
    fn lwe_dimension(&self) -> LweDimension;
}
