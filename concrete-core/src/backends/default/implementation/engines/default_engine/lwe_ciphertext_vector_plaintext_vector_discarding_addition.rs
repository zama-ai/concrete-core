use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, PlaintextVector32, PlaintextVector64,
};
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::specification::engines::{
    LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine,
    LweCiphertextVectorPlaintextVectorDiscardingAdditionError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine<
        LweCiphertextVector32,
        PlaintextVector32,
        LweCiphertextVector32,
    > for DefaultEngine
{
    fn discard_add_lwe_ciphertext_vector_plaintext_vector(
        &mut self,
        output: &mut LweCiphertextVector32,
        input_1: &LweCiphertextVector32,
        input_2: &PlaintextVector32,
    ) -> Result<(), LweCiphertextVectorPlaintextVectorDiscardingAdditionError<Self::EngineError>>
    {
        LweCiphertextVectorPlaintextVectorDiscardingAdditionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe {
            self.discard_add_lwe_ciphertext_vector_plaintext_vector_unchecked(
                output, input_1, input_2,
            )
        };
        Ok(())
    }

    unsafe fn discard_add_lwe_ciphertext_vector_plaintext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input_1: &LweCiphertextVector32,
        input_2: &PlaintextVector32,
    ) {
        for (mut out, inp) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter())
        {
            out.as_mut_tensor().fill_with_copy(inp.as_tensor());
        }
        for (mut out, inp) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_2.0.plaintext_iter())
        {
            out.get_mut_body().0 = out.get_body().0.wrapping_add(inp.0);
        }
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorPlaintextVectorDiscardingAdditionEngine<
        LweCiphertextVector64,
        PlaintextVector64,
        LweCiphertextVector64,
    > for DefaultEngine
{
    fn discard_add_lwe_ciphertext_vector_plaintext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input_1: &LweCiphertextVector64,
        input_2: &PlaintextVector64,
    ) -> Result<(), LweCiphertextVectorPlaintextVectorDiscardingAdditionError<Self::EngineError>>
    {
        LweCiphertextVectorPlaintextVectorDiscardingAdditionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe {
            self.discard_add_lwe_ciphertext_vector_plaintext_vector_unchecked(
                output, input_1, input_2,
            )
        };
        Ok(())
    }

    unsafe fn discard_add_lwe_ciphertext_vector_plaintext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input_1: &LweCiphertextVector64,
        input_2: &PlaintextVector64,
    ) {
        for (mut out, inp) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter())
        {
            out.as_mut_tensor().fill_with_copy(inp.as_tensor());
        }
        for (mut out, inp) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_2.0.plaintext_iter())
        {
            out.get_mut_body().0 = out.get_body().0.wrapping_add(inp.0);
        }
    }
}
