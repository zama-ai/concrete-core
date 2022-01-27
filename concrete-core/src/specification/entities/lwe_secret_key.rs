use crate::specification::entities::markers::{KeyDistributionMarker, LweSecretKeyKind};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::LweDimension;

/// A trait implemented by types embodying an LWE secret key.
///
/// An LWE secret key is associated with a
/// [`KeyDistribution`](`LweSecretKeyEntity::KeyDistribution`) type, which conveys its distribution.
///
/// # Formal Definition
///
/// ## LWE Secret Key
///
/// We consider a secret key:
/// $$\vec{s} \in \mathbb{Z}^n$$
/// This vector contains $n$ integers that have been sampled for some distribution which is either
/// uniformly binary, uniformly ternary, gaussian or even uniform.
pub trait LweSecretKeyEntity: AbstractEntity<Kind = LweSecretKeyKind> {
    /// The distribution of this key.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the LWE dimension of the key.
    fn lwe_dimension(&self) -> LweDimension;
}
