use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayFusingOppositeError for LweCiphertextArrayFusingOppositeEngine @
}

/// A trait for engines computing the opposite (fusing) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation computes the opposite of the `input` LWE
/// ciphertext array.
///
///  # Formal Definition
pub trait LweCiphertextArrayFusingOppositeEngine<CiphertextArray>: AbstractEngine
where
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Computes the opposite of an LWE ciphertext array.
    fn fuse_opp_lwe_ciphertext_array(
        &mut self,
        input: &mut CiphertextArray,
    ) -> Result<(), LweCiphertextArrayFusingOppositeError<Self::EngineError>>;

    /// Unsafely computes the opposite of an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayFusingOppositeError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_opp_lwe_ciphertext_array_unchecked(&mut self, input: &mut CiphertextArray);
}
