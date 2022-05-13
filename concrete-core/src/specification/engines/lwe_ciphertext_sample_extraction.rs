use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GlweCiphertextEntity, LweCiphertextEntity};
use concrete_commons::parameters::{MonomialIndex};

engine_error! {
    LweCiphertextSampleExtractionError for LweCiphertextSampleExtractionEngine @
    MonomialIndexTooLarge => "The monomial index must be smaller than the GLWE polynomial size."
}

impl<EngineError: std::error::Error> LweCiphertextSampleExtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<GlweCiphertext>(
        input: &GlweCiphertext,
        nth: MonomialIndex,
    ) -> Result<(), Self>
        where
            GlweCiphertext: GlweCiphertextEntity,
    {
        if nth.0 >= input.polynomial_size().0 {
            return Err(Self::MonomialIndexTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines extracting an LWE ciphertext from GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext containing
/// the extraction of the `nth` coefficient of the `input` GLWE ciphertext.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
pub trait LweCiphertextSampleExtractionEngine<GlweCiphertext, LweCiphertext>:
AbstractEngine
    where
        GlweCiphertext: GlweCiphertextEntity,
        LweCiphertext: LweCiphertextEntity<KeyDistribution = GlweCiphertext::KeyDistribution>,
{
    /// Extracts an LWE ciphertext from a GLWE ciphertext.
    fn sample_extract_lwe_ciphertext(
        &mut self,
        input: &GlweCiphertext,
        nth: MonomialIndex,
    ) -> Result<LweCiphertext, LweCiphertextSampleExtractionError<Self::EngineError>>;

    /// Unsafely extracts an LWE ciphertext from a GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextSampleExtractionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn sample_extract_lwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext,
        nth: MonomialIndex,
    ) -> LweCiphertext;
}
