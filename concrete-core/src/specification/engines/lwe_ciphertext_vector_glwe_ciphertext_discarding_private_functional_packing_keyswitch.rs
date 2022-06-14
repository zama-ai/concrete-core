use super::engine_error;
use crate::prelude::{GlweCiphertextEntity, PrivateFunctionalPackingKeyswitchKeyEntity};
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError for
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext vector and input private functional packing \
                                 keyswitch key LWE dimension must be the same.",
    OutputGlweDimensionMismatch => "The output ciphertext vector and private functional packing \
                                   keyswitch key output GLWE dimensions must be the same.",
    OutputPolynomialSizeMismatch => "The output ciphertext vector and private functional packing \
                                    keyswitch key polynomial sizes must be the same.",
    CiphertextCountMismatch => "The input ciphertext count is bigger than the output polynomial \
                               size."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<
        PrivateFunctionalPackingKeyswitchKey,
        InputCiphertextVector,
        OutputCiphertext,
    >(
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        ksk: &PrivateFunctionalPackingKeyswitchKey,
    ) -> Result<(), Self>
    where
        PrivateFunctionalPackingKeyswitchKey: PrivateFunctionalPackingKeyswitchKeyEntity,
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

/// A trait for engines implementing private functional packing keyswitching (discarding) LWE
/// ciphertext vectors into a GLWE ciphertext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext
/// with the private functional packing keyswitch of the `input` LWE ciphertext vector, under the
/// `pfpksk` private functional packing keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
    PrivateFunctionalPackingKeyswitchKey,
    InputCiphertextVector,
    OutputCiphertext,
>: AbstractEngine where
    PrivateFunctionalPackingKeyswitchKey: PrivateFunctionalPackingKeyswitchKeyEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertext: GlweCiphertextEntity,
{
    /// Keyswitches an LWE ciphertext vector using a private functional packing keyswitch key.
    fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pfpksk: &PrivateFunctionalPackingKeyswitchKey,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    >;

    /// Unsafely keyswitches an LWE ciphertext vector using a private functional packing
    /// keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pfpksk: &PrivateFunctionalPackingKeyswitchKey,
    );
}
