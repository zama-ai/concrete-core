use super::engine_error;
use crate::prelude::LweCiphertextIndex;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextArrayEntity, LweCiphertextEntity};

engine_error! {
    LweCiphertextDiscardingLoadingError for LweCiphertextDiscardingLoadingEngine @
    LweDimensionMismatch => "The output and input LWE dimension must be the same.",
    IndexTooLarge => "The index must not exceed the size of the array."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<CiphertextArray, Ciphertext>(
        ciphertext: &Ciphertext,
        array: &CiphertextArray,
        i: LweCiphertextIndex,
    ) -> Result<(), Self>
    where
        Ciphertext: LweCiphertextEntity,
        CiphertextArray: LweCiphertextArrayEntity,
    {
        if ciphertext.lwe_dimension() != array.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if i.0 >= array.lwe_ciphertext_count().0 {
            return Err(Self::IndexTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines loading (discarding) an LWE ciphertext from a LWE ciphertext array.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `ciphertext` LWE ciphertext
/// with the `i`th LWE ciphertext of the `array` LWE ciphertext array.
///
/// # Formal Definition
pub trait LweCiphertextDiscardingLoadingEngine<CiphertextArray, Ciphertext>:
    AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Loads an LWE ciphertext from an LWE ciphertext array.
    fn discard_load_lwe_ciphertext(
        &mut self,
        ciphertext: &mut Ciphertext,
        array: &CiphertextArray,
        i: LweCiphertextIndex,
    ) -> Result<(), LweCiphertextDiscardingLoadingError<Self::EngineError>>;

    /// Unsafely loads an LWE ciphertext from an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingLoadingError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_load_lwe_ciphertext_unchecked(
        &mut self,
        ciphertext: &mut Ciphertext,
        array: &CiphertextArray,
        i: LweCiphertextIndex,
    );
}
