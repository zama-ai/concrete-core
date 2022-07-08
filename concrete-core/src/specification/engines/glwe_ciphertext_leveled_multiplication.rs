use crate::prelude::{GlweRelinearizationKeyEntity, ScalingFactor};
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GgswCiphertextEntity, GlweCiphertextEntity};

use super::engine_error;

engine_error! {
    GlweCiphertextLeveledMultiplicationError for
    GlweCiphertextLeveledMultiplicationEngine @
    PolynomialSizeMismatch => "The two input GLWE ciphertexts and the relinearization key \
    polynomial sizes must be the same.",
    GlweDimensionMismatch => "The two input GLWE ciphertexts and the relinearization key GLWE \
    dimension must be the same.",
    NegativeScaleError => "The scaling factor for the leveled multiplication must be stricly \
    greater than zero."
}

impl<EngineError: std::error::Error> GlweCiphertextLeveledMultiplicationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<GlweCiphertext, RelinearizationKey>(
        glwe_input_1: &GlweCiphertext,
        glwe_input_2: &GlweCiphertext,
        rlk: &RelinearizationKey,
        scale: ScalingFactor,
    ) -> Result<(), Self>
    where
        GlweCiphertext: GlweCiphertextEntity,
        RelinearizationKey: RelinearizationKeyEntity,
    {
        if scale.0 <= 0 {
            return Err(Self::NegativeScaleError);
        }
        if glwe_input_1.polynomial_size().0 != glwe_input_2.polynomial_size().0 {
            return Err(Self::PolynomialSizeMismatch);
        }
        if glwe_input_1.polynomial_size().0 != rlk.polynomial_size().0 {
            return Err(Self::PolynomialSizeMismatch);
        }
        if glwe_input_1.glwe_dimension().0 != glwe_input_2.glwe_dimension().0 {
            return Err(Self::GlweDimensionMismatch);
        }
        if glwe_input_1.glwe_dimension().0 != rlk.glwe_dimension().0 {
            return Err(Self::GlweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines computing the leveled multiplication between two GLWE ciphertexts
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext containing
/// the result of the leveled multiplication between `glwe_input_1` and `glwe_input_2` GLWE 
/// ciphertexts, using a relinearization key `rlk` and a scaling factor `scaling_factor`.
///
/// # Formal Definition
/// This function takes as input two
/// [GLWE ciphertexts](`crate::specification::entities::GlweCiphertextEntity`) $c\_1$ and $c\_2$,
/// which encrypt $m_1$ and $m_2$ respectively, a
/// [relinearization key](`crate::specification::entities::GlweRelinearizationKeyEntity) $RLK$, and
/// a scaling factor `scale`, and outputs a new
/// [GLWE ciphertexts](`crate::specification::entities::GlweCiphertextEntity`) $c$ which contains
/// an encryption of $(m\_1 m\_2)/scale$.

pub trait GlweCiphertextLeveledMultiplicationEngine<GlweInput, RelinearizationKey, Output>:
    AbstractEngine
where
    GlweInput: GlweCiphertextEntity,
    RelinearizationKey: GlweRelinearizationKeyEntity<KeyDistribution = GlweInput::KeyDistribution>,
    Output: GlweCiphertextEntity<KeyDistribution = GlweInput::KeyDistribution>,
{
    /// Computes the leveled multiplication between two GLWE ciphertexts
    fn compute_leveled_multiplication_glwe_ciphertexts(
        &mut self,
        glwe_input_1: &GlweInput,
        glwe_input_2: &GlweInput,
        rlk: &RelinearizationKey,
        scale: ScalingFactor,
    ) -> Result<Output, GlweCiphertextLeveledMultiplicationError<Self::EngineError>>;

    /// Unsafely computes the leveled multiplication between two GLWE ciphertexts
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextLeveledMultiplicationError`]. For safety concerns _specific_ to
    /// an engine, refer to the implementer safety section.
    unsafe fn compute_leveled_multiplication_glwe_ciphertexts_unchecked(
        &mut self,
        glwe_input_1: &GlweInput,
        glwe_input_2: &GlweInput,
        rlk: &RelinearizationKey,
        scale: ScalingFactor,
    ) -> Output;
}
