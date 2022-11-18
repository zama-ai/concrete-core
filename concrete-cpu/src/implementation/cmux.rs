use super::external_product::external_product;
use super::fft::FftView;
use super::types::*;
use crate::implementation::external_product::external_product_scratch;
use dyn_stack::{DynStack, SizeOverflow, StackReq};

/// Returns the required memory for [`cmux`].
pub fn cmux_scratch(
    ggsw_polynomial_size: PolynomialSize,
    ggsw_glwe_dimension: GlweDimension,
    ggsw_row_count: usize,
    ggsw_decomposition_level_count: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    external_product_scratch(
        ggsw_polynomial_size,
        ggsw_glwe_dimension,
        ggsw_row_count,
        ggsw_decomposition_level_count,
        fft,
    )
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux(
    ct0: GlweCiphertext<&mut [u64]>,
    ct1: GlweCiphertext<&mut [u64]>,
    fourier_ggsw: GgswCiphertext<&[f64]>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    let mut ct1 = ct1;
    izip!(ct1.as_mut_view().into_data(), ct0.as_view().into_data()).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub(*c0);
    });
    external_product(ct0, fourier_ggsw, ct1.as_view(), fft, stack);
}
