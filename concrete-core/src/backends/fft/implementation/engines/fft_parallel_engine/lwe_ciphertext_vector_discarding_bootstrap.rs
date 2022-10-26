use crate::prelude::{
    FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64, FftParallelEngine, FftParallelError,
    GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphertextVectorEntity,
    GlweCiphertextView32, GlweCiphertextView64, LweCiphertextDiscardingBootstrapEngine,
    LweCiphertextMutView32, LweCiphertextMutView64, LweCiphertextVector32, LweCiphertextVector64,
    LweCiphertextVectorDiscardingBootstrapEngine, LweCiphertextVectorDiscardingBootstrapError,
    LweCiphertextView32, LweCiphertextView64, FFT_ENGINE,
};
use rayon::prelude::*;

impl From<FftParallelError> for LweCiphertextVectorDiscardingBootstrapError<FftParallelError> {
    fn from(err: FftParallelError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextVectorDiscardingBootstrapEngine<
        FftFourierLweBootstrapKey32,
        GlweCiphertextVector32,
        LweCiphertextVector32,
        LweCiphertextVector32,
    > for FftParallelEngine
{
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertextVector32,
        acc: &GlweCiphertextVector32,
        bsk: &FftFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<FftParallelError>> {
        LweCiphertextVectorDiscardingBootstrapError::perform_generic_checks(
            output, input, acc, bsk,
        )?;
        FftParallelError::perform_fft_checks(acc.polynomial_size())?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_vector_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertextVector32,
        acc: &GlweCiphertextVector32,
        bsk: &FftFourierLweBootstrapKey32,
    ) {
        input
            .0
            .par_ciphertext_iter()
            .zip(output.0.par_ciphertext_iter_mut())
            .zip(acc.0.par_ciphertext_iter())
            .for_each(|((c, o), a)| {
                let c1 = LweCiphertextView32(c);
                let a1 = GlweCiphertextView32(a);
                let mut o1 = LweCiphertextMutView32(o);
                FFT_ENGINE.with(|e| {
                    e.borrow_mut()
                        .discard_bootstrap_lwe_ciphertext(&mut o1, &c1, &a1, bsk)
                        .unwrap();
                });
            });
    }
}

impl
    LweCiphertextVectorDiscardingBootstrapEngine<
        FftFourierLweBootstrapKey64,
        GlweCiphertextVector64,
        LweCiphertextVector64,
        LweCiphertextVector64,
    > for FftParallelEngine
{
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
        acc: &GlweCiphertextVector64,
        bsk: &FftFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<FftParallelError>> {
        LweCiphertextVectorDiscardingBootstrapError::perform_generic_checks(
            output, input, acc, bsk,
        )?;
        FftParallelError::perform_fft_checks(acc.polynomial_size())?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_vector_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
        acc: &GlweCiphertextVector64,
        bsk: &FftFourierLweBootstrapKey64,
    ) {
        input
            .0
            .par_ciphertext_iter()
            .zip(output.0.par_ciphertext_iter_mut())
            .zip(acc.0.par_ciphertext_iter())
            .for_each(|((c, o), a)| {
                let c1 = LweCiphertextView64(c);
                let a1 = GlweCiphertextView64(a);
                let mut o1 = LweCiphertextMutView64(o);
                FFT_ENGINE.with(|e| {
                    e.borrow_mut()
                        .discard_bootstrap_lwe_ciphertext(&mut o1, &c1, &a1, bsk)
                        .unwrap();
                });
            });
    }
}
