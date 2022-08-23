use super::engine_error;
use crate::prelude::{FunctionalPackingKeyswitchKeyEntity, GlweCiphertextEntity};
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::LweCiphertextVectorEntity;

//TODO: check if the errors make sense
engine_error! {
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError for
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext vector and input functional packing \
    keyswitch key LWE \
                                    dimension must be the same.",
    OutputGlweDimensionMismatch => "The output ciphertext vector and functional packing keyswitch \
    key output \
                                    GLWE dimensions must be the same.",
    OutputPolynomialSizeMismatch => "The output ciphertext vector and functional packing keyswitch \
    key \
                                    polynomial sizes must be the same.",
    CiphertextCountMismatch => "The input ciphertext count is bigger than the output polynomial \
                                    size."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<
        FunctionalPackingKeyswitchKey,
        InputCiphertextVector,
        OutputCiphertext,
    >(
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        ksk: &FunctionalPackingKeyswitchKey,
    ) -> Result<(), Self>
    where
        FunctionalPackingKeyswitchKey: FunctionalPackingKeyswitchKeyEntity,
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertext: GlweCiphertextEntity,
    {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if output.glwe_dimension() != ksk.output_glwe_dimension() {
            return Err(Self::OutputGlweDimensionMismatch);
        }

        if output.polynomial_size() != ksk.output_polynomial_size() {
            return Err(Self::OutputPolynomialSizeMismatch);
        }

        if input.lwe_ciphertext_count().0 > output.polynomial_size().0 {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines functional packing keyswitching (discarding) LWE ciphertext vectors into a
/// GLWE
/// ciphertext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext
/// with the functional packing keyswitch of the `input` LWE ciphertext vector, under the `pksk`
/// functional packing
/// keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine<
    FunctionalPackingKeyswitchKey,
    InputCiphertextVector,
    OutputCiphertext,
>: AbstractEngine where
    FunctionalPackingKeyswitchKey: FunctionalPackingKeyswitchKeyEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertext: GlweCiphertextEntity,
{
    /// Functional Packing keyswitch an LWE ciphertext vector.
    fn discard_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pksk: &FunctionalPackingKeyswitchKey,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    >;

    /// Unsafely functional packing keyswitches an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError`]. For
    /// safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pksk: &FunctionalPackingKeyswitchKey,
    );
}
