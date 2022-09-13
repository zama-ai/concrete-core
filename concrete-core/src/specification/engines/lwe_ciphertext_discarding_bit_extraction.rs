use super::engine_error;
use crate::prelude::{
    AbstractEngine, CiphertextModulusLog, DeltaLog, ExtractedBitsCount, LweBootstrapKeyEntity,
    LweCiphertextArrayEntity, LweCiphertextEntity, LweKeyswitchKeyEntity,
};

engine_error! {
    LweCiphertextDiscardingBitExtractError for LweCiphertextDiscardingBitExtractEngine @
    InputLweDimensionMismatch => "The input ciphertext and bootstrap key LWE dimension must be the \
                                  same.",
    InputKeyswitchKeyLweDimensionMismatch => "The input ciphertext LWE dimension must be the same \
                                            as the keyswitch key input LWE dimension.",
    OutputLweDimensionMismatch => "The output ciphertext array LWE dimension must be the same \
                                  as the output LWE dimension of the keyswitch key.",
    ExtractedBitsCountMismatch => "The output LWE ciphertext array count must be the same as \
                                  the number of bits to extract.",
    KeyDimensionMismatch => "The keyswitch key output LWE dimension must be the same as the \
                            bootstrap key input LWE dimension.",
    NotEnoughBitsToExtract => "The number of bits to extract, starting from the bit at index  \
                              delta_log towards the most significant bits, should not exceed the \
                              total number of available bits in the ciphertext."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingBitExtractError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<
        BootstrapKey,
        KeyswitchKey,
        InputCiphertext,
        OutputCiphertextArray,
    >(
        output: &OutputCiphertextArray,
        input: &InputCiphertext,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        extracted_bits_count: ExtractedBitsCount,
        ciphertext_modulus_log: CiphertextModulusLog,
        delta_log: DeltaLog,
    ) -> Result<(), Self>
    where
        BootstrapKey: LweBootstrapKeyEntity,
        KeyswitchKey: LweKeyswitchKeyEntity,
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertextArray: LweCiphertextArrayEntity,
    {
        if input.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputKeyswitchKeyLweDimensionMismatch);
        }
        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }
        if output.lwe_ciphertext_count().0 != extracted_bits_count.0 {
            return Err(Self::ExtractedBitsCountMismatch);
        }
        if ksk.output_lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(Self::KeyDimensionMismatch);
        }
        if ciphertext_modulus_log.0 < extracted_bits_count.0 + delta_log.0 {
            return Err(Self::NotEnoughBitsToExtract);
        }
        Ok(())
    }
}

/// A trait for engines doing a (discarding) bit extract over LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the bit extraction of the `input` LWE ciphertext, extracting `number_of_bits_to_extract`
/// bits starting from the bit at index `delta_log` (0-indexed) included, and going towards the
/// most significant bits.
///
/// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct LWE
/// ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most significant bit
/// in the plaintext representation).
///
/// # Formal Definition
pub trait LweCiphertextDiscardingBitExtractEngine<
    BootstrapKey,
    KeyswitchKey,
    InputCiphertext,
    OutputCiphertextArray,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Extract bits of an LWE ciphertext.
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertext,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>>;

    /// Unsafely extract bits of an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingBitExtractError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertextArray,
        input: &InputCiphertext,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    );
}
