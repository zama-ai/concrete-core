use crate::backends::multithread::engines::MultithreadEngine;
use crate::prelude::{FourierLweBootstrapKey32, FourierLweBootstrapKey64, GlweCiphertextVector32, GlweCiphertextVector64, LweBootstrapKeyEntity, LweCiphertextVector32, LweCiphertextVector64, LweCiphertextVectorDiscardingBootstrapEngine, LweCiphertextVectorDiscardingBootstrapError};

// This POC implementation does not reflect how we would normally implement this operation (using
// rayon). For an example of multithreaded operation which uses rayon the way we want to, see the
// bootstrap key creation.
impl
    LweCiphertextVectorDiscardingBootstrapEngine<
        FourierLweBootstrapKey32,
        GlweCiphertextVector32,
        LweCiphertextVector32,
        LweCiphertextVector32,
    > for MultithreadEngine
{
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertextVector32,
        acc: &GlweCiphertextVector32,
        bsk: &FourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<Self::EngineError>> {
        LweCiphertextVectorDiscardingBootstrapError::perform_generic_checks(
            output, input, acc, bsk,
        )?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_vector_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertextVector32,
        acc: &GlweCiphertextVector32,
        bsk: &FourierLweBootstrapKey32,
    ) {
        let buffers =
            self.get_fourier_u32_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());

        crossbeam::thread::scope(|s| {
            output
                .0
                .ciphertext_iter_mut()
                .zip(input.0.ciphertext_iter())
                .zip(acc.0.ciphertext_iter())
                .map(|((mut output_ciphertext, input_ciphertext), accumulator)| {
                    let mut local_buffers = buffers.clone();
                    s.spawn(move |_| {
                        bsk.0.bootstrap(
                            &mut output_ciphertext,
                            &input_ciphertext,
                            &accumulator,
                            &mut local_buffers,
                        )
                    })
                })
                .for_each(|handle| handle.join().unwrap());
        })
        .unwrap();
    }
}
impl
LweCiphertextVectorDiscardingBootstrapEngine<
    FourierLweBootstrapKey64,
    GlweCiphertextVector64,
    LweCiphertextVector64,
    LweCiphertextVector64,
> for MultithreadEngine
{
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
        acc: &GlweCiphertextVector64,
        bsk: &FourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<Self::EngineError>> {
        LweCiphertextVectorDiscardingBootstrapError::perform_generic_checks(
            output, input, acc, bsk,
        )?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_vector_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
        acc: &GlweCiphertextVector64,
        bsk: &FourierLweBootstrapKey64,
    ) {
        let buffers =
            self.get_fourier_u64_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());

        crossbeam::thread::scope(|s| {
            output
                .0
                .ciphertext_iter_mut()
                .zip(input.0.ciphertext_iter())
                .zip(acc.0.ciphertext_iter())
                .map(|((mut output_ciphertext, input_ciphertext), accumulator)| {
                    let mut local_buffers = buffers.clone();
                    s.spawn(move |_| {
                        bsk.0.bootstrap(
                            &mut output_ciphertext,
                            &input_ciphertext,
                            &accumulator,
                            &mut local_buffers,
                        )
                    })
                })
                .for_each(|handle| handle.join().unwrap());
        })
            .unwrap();
    }
}
