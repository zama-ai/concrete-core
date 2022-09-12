use super::engine_error;
use crate::prelude::LweCiphertextRange;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayLoadingError for LweCiphertextArrayLoadingEngine @
    UnorderedInputRange => "The input range bounds must be ordered.",
    OutOfArrayInputRange => "The input array must contain the input range."
}

impl<EngineError: std::error::Error> LweCiphertextArrayLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<CiphertextArray, SubCiphertextArray>(
        array: &CiphertextArray,
        range: LweCiphertextRange,
    ) -> Result<(), Self>
    where
        CiphertextArray: LweCiphertextArrayEntity,
        SubCiphertextArray: LweCiphertextArrayEntity,
    {
        if !range.is_ordered() {
            return Err(Self::UnorderedInputRange);
        }

        if range.1 >= array.lwe_ciphertext_count().0 {
            return Err(Self::OutOfArrayInputRange);
        }
        Ok(())
    }
}

/// A trait for engines loading a sub LWE ciphertext array from another one.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext array containing
/// a piece of the `array` LWE ciphertext array.
///
/// # Formal Definition
pub trait LweCiphertextArrayLoadingEngine<CiphertextArray, SubCiphertextArray>:
    AbstractEngine
where
    CiphertextArray: LweCiphertextArrayEntity,
    SubCiphertextArray: LweCiphertextArrayEntity,
{
    /// Loads a subpart of an LWE ciphertext array.
    fn load_lwe_ciphertext_array(
        &mut self,
        array: &CiphertextArray,
        range: LweCiphertextRange,
    ) -> Result<SubCiphertextArray, LweCiphertextArrayLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayLoadingError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn load_lwe_ciphertext_array_unchecked(
        &mut self,
        array: &CiphertextArray,
        range: LweCiphertextRange,
    ) -> SubCiphertextArray;
}
