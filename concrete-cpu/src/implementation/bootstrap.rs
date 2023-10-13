use crate::implementation::cmux::cmux_scratch;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::*;

use super::cmux::cmux;
use super::fft::FftView;
use super::polynomial::{
    update_with_wrapping_monic_monomial_mul, update_with_wrapping_unit_monomial_div,
};
use super::types::*;
use super::Split;

impl<'a> BootstrapKey<&'a [f64]> {
    pub fn blind_rotate_scratch(
        bsk_polynomial_size: PolynomialSize,
        bsk_glwe_dimension: GlweDimension,
        bsk_row_count: usize,
        bsk_decomposition_level_count: DecompositionLevelCount,
        bsk_input_lwe_dimension: LweDimension,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        unused!(bsk_input_lwe_dimension);

        StackReq::try_all_of([
            StackReq::try_new_aligned::<u64>(
                bsk_glwe_dimension.as_glwe_size().0 * bsk_polynomial_size.0,
                CACHELINE_ALIGN,
            )?,
            cmux_scratch(
                bsk_polynomial_size,
                bsk_glwe_dimension,
                bsk_row_count,
                bsk_decomposition_level_count,
                fft,
            )?,
        ])
    }

    pub fn bootstrap_scratch(
        bsk_polynomial_size: PolynomialSize,
        bsk_glwe_dimension: GlweDimension,
        bsk_row_count: usize,
        bsk_decomposition_level_count: DecompositionLevelCount,
        bsk_input_lwe_dimension: LweDimension,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        StackReq::try_all_of([
            StackReq::try_new_aligned::<u64>(
                bsk_glwe_dimension.as_glwe_size().0 * bsk_polynomial_size.0,
                CACHELINE_ALIGN,
            )?,
            Self::blind_rotate_scratch(
                bsk_polynomial_size,
                bsk_glwe_dimension,
                bsk_row_count,
                bsk_decomposition_level_count,
                bsk_input_lwe_dimension,
                fft,
            )?,
        ])
    }

    pub fn blind_rotate(
        self,
        lut: GlweCiphertext<&mut [u64]>,
        lwe: LweCiphertext<&[u64]>,
        fft: FftView<'_>,
        mut stack: DynStack<'_>,
    ) {
        let mut lut = lut;
        let (lwe_body, lwe_mask) = lwe.into_data().split_last().unwrap();

        let lut_poly_size = lut.polynomial_size;
        let modulus_switched_body = pbs_modulus_switch(
            *lwe_body,
            lut_poly_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        );
        let lut_polynomial_size = lut.polynomial_size.0;
        lut.as_mut_view()
            .into_data()
            .into_chunks(lut_polynomial_size)
            .for_each(|polynomial| {
                update_with_wrapping_unit_monomial_div(polynomial, modulus_switched_body);
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), self.into_ggsw_iter())
        {
            if *lwe_mask_element != 0 {
                let stack = stack.rb_mut();
                // We copy ct_0 to ct_1
                let (mut ct1, stack) = stack
                    .collect_aligned(CACHELINE_ALIGN, ct0.as_view().into_data().iter().copied());
                let mut ct1 =
                    GlweCiphertext::new(&mut *ct1, ct0.polynomial_size, ct0.glwe_dimension);

                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{modulus_switched_mask_element}
                let polynomial_size = ct1.polynomial_size.0;
                let modulus_switched_mask_element = pbs_modulus_switch(
                    *lwe_mask_element,
                    lut_poly_size,
                    ModulusSwitchOffset(0),
                    LutCountLog(0),
                );
                for polynomial in ct1.as_mut_view().into_data().into_chunks(polynomial_size) {
                    update_with_wrapping_monic_monomial_mul(
                        polynomial,
                        modulus_switched_mask_element,
                    );
                }

                cmux(
                    ct0.as_mut_view(),
                    ct1.as_mut_view(),
                    bootstrap_key_ggsw,
                    fft,
                    stack,
                );
            }
        }
    }

    pub fn bootstrap(
        self,
        lwe_out: LweCiphertext<&mut [u64]>,
        lwe_in: LweCiphertext<&[u64]>,
        accumulator: GlweCiphertext<&[u64]>,
        fft: FftView<'_>,
        stack: DynStack<'_>,
    ) {
        let (mut local_accumulator_data, stack) = stack.collect_aligned(
            CACHELINE_ALIGN,
            accumulator.as_view().into_data().iter().copied(),
        );
        let mut local_accumulator = GlweCiphertext::new(
            &mut *local_accumulator_data,
            accumulator.polynomial_size,
            accumulator.glwe_dimension,
        );
        self.blind_rotate(local_accumulator.as_mut_view(), lwe_in, fft, stack);
        local_accumulator
            .as_view()
            .fill_lwe_with_sample_extraction(lwe_out, 0);
    }
}

/// This function switches modulus for a single coefficient of a ciphertext,
/// only in the context of a PBS
///
/// offset: the number of msb discarded
/// lut_count_log: the right padding
pub fn pbs_modulus_switch(
    input: u64,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> usize {
    // First, do the left shift (we discard the offset msb)
    let mut output = input << offset.0;
    // Start doing the right shift
    output >>= u64::BITS as usize - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += output & 1_u64;
    // Finish the right shift
    output >>= 1;
    // Apply the lsb padding
    output <<= lut_count_log.0;
    output as usize
}
