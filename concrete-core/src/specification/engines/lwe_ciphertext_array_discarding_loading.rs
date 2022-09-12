use super::engine_error;
use crate::prelude::LweCiphertextRange;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayDiscardingLoadingError for LweCiphertextArrayDiscardingLoadingEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    UnorderedInputRange => "The input range bounds must be ordered.",
    OutOfArrayInputRange => "The input array must contain the input range.",
    UnorderedOutputRange => "The output range bound must be ordered.",
    OutOfArrayOutputRange => "The output array must contain the output range.",
    RangeSizeMismatch => "The input and output range must have the same size."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertextArray, OutputCiphertextArray>(
        output_array: &OutputCiphertextArray,
        input_array: &InputCiphertextArray,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    ) -> Result<(), Self>
    where
        InputCiphertextArray: LweCiphertextArrayEntity,
        OutputCiphertextArray: LweCiphertextArrayEntity,
    {
        if input_array.lwe_dimension() != output_array.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if !input_range.is_ordered() {
            return Err(Self::UnorderedInputRange);
        }

        if !output_range.is_ordered() {
            return Err(Self::UnorderedOutputRange);
        }

        if output_range.1 >= output_array.lwe_ciphertext_count().0 {
            return Err(Self::OutOfArrayOutputRange);
        }

        if input_range.1 >= input_array.lwe_ciphertext_count().0 {
            return Err(Self::OutOfArrayInputRange);
        }

        let input_range_size = input_range.1 - input_range.0;
        let output_range_size = output_range.1 - output_range.0;
        if input_range_size != output_range_size {
            return Err(Self::RangeSizeMismatch);
        }

        Ok(())
    }
}

/// A trait for engines loading (discarding) a sub LWE ciphertext array from another one.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills a piece of the `output_array` lwe
/// ciphertext array with a piece of the `input_array` LWE ciphertext array.
///
/// # Formal Definition
pub trait LweCiphertextArrayDiscardingLoadingEngine<InputCiphertextArray, OutputCiphertextArray>:
    AbstractEngine
where
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Loads a subpart of an LWE ciphertext array into another LWE ciphertext array.
    fn discard_load_lwe_ciphertext_array(
        &mut self,
        output_array: &mut OutputCiphertextArray,
        input_array: &InputCiphertextArray,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    ) -> Result<(), LweCiphertextArrayDiscardingLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an LWE ciphertext array into another LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingLoadingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_load_lwe_ciphertext_array_unchecked(
        &mut self,
        output_array: &mut OutputCiphertextArray,
        input_array: &InputCiphertextArray,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    );
}
