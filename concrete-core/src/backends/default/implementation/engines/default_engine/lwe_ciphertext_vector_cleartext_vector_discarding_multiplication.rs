use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    CleartextVector32, CleartextVector64, LweCiphertextVector32, LweCiphertextVector64,
};
use crate::specification::engines::{
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine,
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine<
        LweCiphertextVector32,
        CleartextVector32,
        LweCiphertextVector32,
    > for DefaultEngine
{
    fn discard_mul_lwe_ciphertext_vector_cleartext_vector(
        &mut self,
        output: &mut LweCiphertextVector32,
        input_1: &LweCiphertextVector32,
        input_2: &CleartextVector32,
    ) -> Result<
        (),
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError<Self::EngineError>,
    > {
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe {
            self.discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
                output, input_1, input_2,
            )
        };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input_1: &LweCiphertextVector32,
        input_2: &CleartextVector32,
    ) {
        let mut inp2 = input_2.0.cleartext_iter();
        for (mut out, inp1) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter())
        {
            out.fill_with_scalar_mul(&inp1, inp2.next().unwrap());
        }
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine<
        LweCiphertextVector64,
        CleartextVector64,
        LweCiphertextVector64,
    > for DefaultEngine
{
    fn discard_mul_lwe_ciphertext_vector_cleartext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input_1: &LweCiphertextVector64,
        input_2: &CleartextVector64,
    ) -> Result<
        (),
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError<Self::EngineError>,
    > {
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe {
            self.discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
                output, input_1, input_2,
            )
        };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input_1: &LweCiphertextVector64,
        input_2: &CleartextVector64,
    ) {
        let mut inp2 = input_2.0.cleartext_iter();
        for (mut out, inp1) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter())
        {
            out.fill_with_scalar_mul(&inp1, inp2.next().unwrap());
        }
    }
}
