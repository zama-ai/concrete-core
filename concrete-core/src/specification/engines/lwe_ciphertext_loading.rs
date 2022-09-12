use super::engine_error;
use crate::prelude::LweCiphertextIndex;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextArrayEntity, LweCiphertextEntity};

engine_error! {
    LweCiphertextLoadingError for LweCiphertextLoadingEngine @
    IndexTooLarge => "The index must not exceed the size of the array."
}

impl<EngineError: std::error::Error> LweCiphertextLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Ciphertext, CiphertextArray>(
        array: &CiphertextArray,
        i: LweCiphertextIndex,
    ) -> Result<(), Self>
    where
        Ciphertext: LweCiphertextEntity,
        CiphertextArray: LweCiphertextArrayEntity,
    {
        if i.0 >= array.lwe_ciphertext_count().0 {
            return Err(Self::IndexTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines loading LWE ciphertexts from LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext containing the
/// `i`th LWE ciphertext of the `array` LWE ciphertext array.
///
/// # Formal Definition
pub trait LweCiphertextLoadingEngine<CiphertextArray, Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Loads an LWE ciphertext from an LWE ciphertext array.
    fn load_lwe_ciphertext(
        &mut self,
        array: &CiphertextArray,
        i: LweCiphertextIndex,
    ) -> Result<Ciphertext, LweCiphertextLoadingError<Self::EngineError>>;

    /// Unsafely loads an LWE ciphertext from an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextLoadingError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn load_lwe_ciphertext_unchecked(
        &mut self,
        array: &CiphertextArray,
        i: LweCiphertextIndex,
    ) -> Ciphertext;
}
