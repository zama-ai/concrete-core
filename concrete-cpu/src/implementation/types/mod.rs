#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LweDimension(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LweSize(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlweDimension(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlweSize(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecompositionBaseLog(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecompositionLevelCount(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecompositionLevel(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolynomialSize(pub usize);

impl PolynomialSize {
    /// Returns the associated [`PolynomialSizeLog`].
    pub fn log2(&self) -> PolynomialSizeLog {
        debug_assert!(self.0.is_power_of_two());
        PolynomialSizeLog((self.0 as f64).log2().ceil() as usize)
    }
}

/// The logarithm of the number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this returns $\log\_2(N)$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolynomialSizeLog(pub usize);

impl PolynomialSizeLog {
    /// Returns the associated [`PolynomialSizeLog`].
    pub fn as_polynomial_size(self) -> PolynomialSize {
        PolynomialSize(1 << self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModulusSwitchOffset(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LutCountLog(pub usize);

impl LweSize {
    pub fn as_lwe_dimension(self) -> LweDimension {
        LweDimension(self.0 - 1)
    }
}
impl LweDimension {
    pub fn as_lwe_size(self) -> LweSize {
        LweSize(self.0 + 1)
    }
}

impl GlweSize {
    pub fn as_glwe_dimension(self) -> GlweDimension {
        GlweDimension(self.0 - 1)
    }
}
impl GlweDimension {
    pub fn as_glwe_size(self) -> GlweSize {
        GlweSize(self.0 + 1)
    }
}

mod ciphertext;
pub use ciphertext::*;

mod glwe_ciphertext;
pub use glwe_ciphertext::*;

mod ggsw_ciphertext;
pub use ggsw_ciphertext::*;

mod bootstrap_key;
pub use bootstrap_key::*;
