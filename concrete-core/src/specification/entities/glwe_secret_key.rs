use crate::specification::entities::markers::{GlweSecretKeyKind, KeyDistributionMarker};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

/// A trait implemented by types embodying a GLWE secret key.
///
/// A GLWE secret key is associated with a
/// [`KeyDistribution`](`GlweSecretKeyEntity::KeyDistribution`) type, which conveys its
/// distribution.
///
/// # Formal Definition
///
/// ## GLWE Secret Key
///
/// We consider a secret key:
/// $$\vec{S} =\left( S\_0, \ldots, S\_{k-1}\right) \in \mathcal{R}^{k}$$
/// The $k$ polynomials composing $\vec{S}$ contain each $N$ integers coefficients that have been
/// sampled from some distribution which is either uniformly binary, uniformly ternary, gaussian or
/// even uniform.
pub trait GlweSecretKeyEntity: AbstractEntity<Kind = GlweSecretKeyKind> {
    /// The distribution of this key.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the GLWE dimension of the key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the key.
    fn polynomial_size(&self) -> PolynomialSize;
}
