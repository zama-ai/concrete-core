use crate::prelude::LweDimension;
use crate::specification::entities::markers::LweSecretKeyKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE secret key.
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
    /// Returns the LWE dimension of the key.
    fn lwe_dimension(&self) -> LweDimension;
}
