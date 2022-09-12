use super::engine_error;
use crate::prelude::{GlweCiphertextEntity, LwePackingKeyswitchKeyEntity};
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::LweCiphertextArrayEntity;

engine_error! {
    LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchError for LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext array and input packing keyswitch key LWE \
                                    dimension must be the same.",
    OutputGlweDimensionMismatch => "The output ciphertext array and packing keyswitch key output \
                                    GLWE dimensions must be the same.",
    OutputPolynomialSizeMismatch => "The output ciphertext array and packing keyswitch key \
                                    polynomial sizes must be the same.",
    CiphertextCountMismatch => "The input ciphertext count is bigger than the output polynomial \
                                    size."
}

impl<EngineError: std::error::Error>
    LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<LwePackingKeyswitchKey, InputCiphertextArray, OutputCiphertext>(
        output: &mut OutputCiphertext,
        input: &InputCiphertextArray,
        ksk: &LwePackingKeyswitchKey,
    ) -> Result<(), Self>
    where
        LwePackingKeyswitchKey: LwePackingKeyswitchKeyEntity,
        InputCiphertextArray: LweCiphertextArrayEntity,
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

/// A trait for engines packing keyswitching (discarding) LWE ciphertext arrays into a GLWE
/// ciphertext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext
/// with the packing keyswitch of the `input` LWE ciphertext array, under the `pksk` packing
/// keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchEngine<
    LwePackingKeyswitchKey,
    InputCiphertextArray,
    OutputCiphertext,
>: AbstractEngine where
    LwePackingKeyswitchKey: LwePackingKeyswitchKeyEntity,
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertext: GlweCiphertextEntity,
{
    /// Packing keyswitch an LWE ciphertext array.
    fn discard_packing_keyswitch_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextArray,
        pksk: &LwePackingKeyswitchKey,
    ) -> Result<
        (),
        LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchError<Self::EngineError>,
    >;

    /// Unsafely packing keyswitches an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_packing_keyswitch_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextArray,
        pksk: &LwePackingKeyswitchKey,
    );
}
