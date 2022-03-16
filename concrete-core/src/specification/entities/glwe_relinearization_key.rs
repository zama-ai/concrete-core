use crate::prelude::markers::GlweRelinearizationKeyKind;
use crate::prelude::DecompositionBaseLog;
use crate::specification::entities::markers::KeyDistributionMarker;
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{DecompositionLevelCount, GlweDimension, PolynomialSize};

/// A trait implemented by types embodying a GLWE relinearization key.
///
/// A GLWE relinearization key is associated with a
/// /// [`KeyDistribution`](`GlweRelinearizationKeyEntity::KeyDistribution`) type, which conveys 
/// the underlying distribution of the GLWE secret key used to create the relinearzation key. 
///
/// # Formal Definition
///
/// ## GLWE Relinearization Key
///
/// For a GLWE secret key $$S$$, we consider the relinearization key to be:
/// $$\vec{RLK} =\left{GLev_{S}^{\beta, \ell}(S_i * S_j) \right}$$
/// where * is multiplication in the ring R_q. $$\beta$$ is the base and $$\ell$$ is the level
/// used in the GLev ciphertext. $$i$$ varies from 0 to $$k - 1$$ and $$j$$ varies from 0 to 
/// $$i - 1$$. The relinearization key is thus a list of $$(k^2 + k) / 2$$ $$Glev$$ ciphertexts, 
/// each encrypting a polynomial product of the input secret key.

pub trait GlweRelinearizationKeyEntity: AbstractEntity<Kind = GlweRelinearizationKeyKind> {
    /// The distribution of the underlying GLWE secret key which is used to generate the
    /// relinearization key.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the GLWE dimension of the underling GLWE secret key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the underlying GLWE secret key.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the level used in the Glev ciphertexts which make up the relinearization key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the base used in the Glev ciphertexts which make up the relinearization key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}
