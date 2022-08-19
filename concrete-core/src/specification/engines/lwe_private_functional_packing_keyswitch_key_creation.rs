use super::engine_error;
use crate::prelude::{
    CleartextVectorEntity, GlweSecretKeyEntity, PrivateFunctionalPackingKeyswitchKeyEntity,
};
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::LweSecretKeyEntity;
use concrete_commons::dispersion::StandardDev;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, PolynomialSize};

engine_error! {
    PrivateFunctionalPackingKeyswitchKeyCreationError for
    PrivateFunctionalPackingKeyswitchKeyCreationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    DifferentPolynomialSizes => "The polynomial size of the output GLWE key is different from \
                                 that of the polynomial scalar defining the function."
}

impl<EngineError: std::error::Error>
    PrivateFunctionalPackingKeyswitchKeyCreationError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks(
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        integer_precision: usize,
        output_key_polynomial_size: PolynomialSize,
        polynomial_scalar_polynomial_size: PolynomialSize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }

        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }

        if decomposition_level_count.0 * decomposition_base_log.0 > integer_precision {
            return Err(Self::DecompositionTooLarge);
        }

        if output_key_polynomial_size != polynomial_scalar_polynomial_size {
            return Err(Self::DifferentPolynomialSizes);
        }
        Ok(())
    }
}

/// A trait for engines creating LWE functional packing keyswitch keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates an LWE private functional packing
/// keyswitch key allowing to switch from the `input_key` LWE secret key to the `output_key` GLWE
/// secret key while applying the private function.
///
/// # Formal Definition
///
/// A private functional packing keyswitch key is a public key which allows to go from a vector
/// of LWE ciphertexts encrypting messages $m\_1,\dotsc,m_t$ under the input secret key, to a GLWE
/// ciphertext under the output secret key encrypting the
/// message $F(m\_1)+F(m\_2) X+\dotsb+F(m\_t) X^{t-1}$ in the ring $\mathbb{Z}\_q\lbrack X\rbrack/
/// (X^N+1)$ for
/// $t<N$ and a scalar function $F\colon\mathbb{Z}\_q\rightarrow\mathbb{Z}\_q\lbrack X\rbrack/
/// (X^n+1)$.
///
/// The scalar function F is defined in terms of the input `polynomial_scalar` as $F(z) =
/// \mathsf{polynomial\\_scalar}\cdot z$, where
/// $\mathsf{polynomial\\_scalar}$ is an element of $\mathbb{Z}\_q\lbrack X\rbrack/(X^n+1)$.
///
/// In particular, creation of a private functional packing keyswitch key takes seven inputs:
/// a [`LWE secret key`](`crate::specification::entities::LweSecretKeyEntity`) for the input
/// secret key, a [`GLWE secret key`](`crate::specification::entities::GlweSecretKeyEntity`) for
/// the output secret key, a
/// [`decomposition level`](`concrete_commons::parameters::DecompositionLevelCount`), a
/// [`decomposition base`](`concrete_commons::parameters::DecompositionBaseLog`), a standard
/// deviation for the [`noise`](`concrete_commons::dispersion::StandardDev`), and finally the
/// input `polynomial_scalar` given as a
/// [`cleartext vector`](`crate::specification::entities::CleartextEntity`) starting from the
/// constant term.
pub trait PrivateFunctionalPackingKeyswitchKeyCreationEngine<
    InputSecretKey,
    OutputSecretKey,
    PrivateFunctionalPackingKeyswitchKey,
    CleartextVector,
    FunctionScalarType,
>: AbstractEngine where
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: GlweSecretKeyEntity,
    CleartextVector: CleartextVectorEntity,
    PrivateFunctionalPackingKeyswitchKey: PrivateFunctionalPackingKeyswitchKeyEntity,
{
    /// Creates a private functional packing keyswitch key.
    #[allow(clippy::too_many_arguments)]
    fn create_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(FunctionScalarType) -> FunctionScalarType,
        polynomial: &CleartextVector,
    ) -> Result<
        PrivateFunctionalPackingKeyswitchKey,
        PrivateFunctionalPackingKeyswitchKeyCreationError<Self::EngineError>,
    >;

    /// Unsafely creates a private functional packing keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PrivateFunctionalPackingKeyswitchKeyCreationError`]. For safety concerns _specific_
    /// to an engine, refer to the implementer safety section.
    #[allow(clippy::too_many_arguments)]
    unsafe fn create_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(FunctionScalarType) -> FunctionScalarType,
        polynomial: &CleartextVector,
    ) -> PrivateFunctionalPackingKeyswitchKey;
}
