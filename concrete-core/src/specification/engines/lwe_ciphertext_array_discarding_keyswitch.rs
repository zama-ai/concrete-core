use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{LweCiphertextArrayEntity, LweKeyswitchKeyEntity};

engine_error! {
    LweCiphertextArrayDiscardingKeyswitchError for LweCiphertextArrayDiscardingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext array and keyswitch key input LWE \
                                  dimension must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext array and keyswitch key output LWE \
                                   dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertexts have different ciphertext counts."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingKeyswitchError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<KeyswitchKey, InputCiphertextArray, OutputCiphertextArray>(
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
        ksk: &KeyswitchKey,
    ) -> Result<(), Self>
    where
        KeyswitchKey: LweKeyswitchKeyEntity,
        InputCiphertextArray: LweCiphertextArrayEntity,
        OutputCiphertextArray: LweCiphertextArrayEntity,
    {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }

        if input.lwe_ciphertext_count() != output.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines keyswitching (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the element-wise keyswitch of the `input` LWE ciphertext array, under the `ksk` lwe
/// keyswitch key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextDiscardingKeyswitchEngine`)
pub trait LweCiphertextArrayDiscardingKeyswitchEngine<
    KeyswitchKey,
    InputCiphertextArray,
    OutputCiphertextArray,
>: AbstractEngine where
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Keyswitch an LWE ciphertext array.
    fn discard_keyswitch_lwe_ciphertext_array(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
        ksk: &KeyswitchKey,
    ) -> Result<(), LweCiphertextArrayDiscardingKeyswitchError<Self::EngineError>>;

    /// Unsafely keyswitch an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingKeyswitchError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_keyswitch_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertextArray,
        ksk: &KeyswitchKey,
    );
}
