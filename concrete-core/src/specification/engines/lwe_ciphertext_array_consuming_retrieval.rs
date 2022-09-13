use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayConsumingRetrievalError for LweCiphertextArrayConsumingRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from an LWE ciphertext
/// array consuming it in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// `input` LWE ciphertext array consuming it in the process.
pub trait LweCiphertextArrayConsumingRetrievalEngine<CiphertextArray, Container>:
    AbstractEngine
where
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Retrieves the content of the container from an LWE ciphertext array, consuming it in the
    /// process.
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: CiphertextArray,
    ) -> Result<Container, LweCiphertextArrayConsumingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from an LWE ciphertext array, consuming
    /// it in the process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayConsumingRetrievalError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: CiphertextArray,
    ) -> Container;
}
