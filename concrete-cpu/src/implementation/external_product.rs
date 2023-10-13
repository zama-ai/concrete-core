use core::mem::MaybeUninit;

use aligned_vec::CACHELINE_ALIGN;
use concrete_fft::c64;
use dyn_stack::{DynArray, DynStack, ReborrowMut, SizeOverflow, StackReq};
use pulp::{as_arrays, as_arrays_mut};

use crate::implementation::decomposer::SignedDecomposer;
use crate::implementation::decomposition::TensorSignedDecompositionLendingIter;
use crate::implementation::{assume_init_mut, Split};

use super::as_mut_uninit;
use super::fft::FftView;
use super::types::*;

impl GgswCiphertext<&mut [f64]> {
    pub fn fill_with_forward_fourier(
        self,
        standard: GgswCiphertext<&[u64]>,
        fft: FftView<'_>,
        stack: DynStack<'_>,
    ) {
        let polynomial_size = standard.polynomial_size.0;

        let mut stack = stack;
        for (fourier_polynomial, standard_polynomial) in izip!(
            self.into_data().into_chunks(polynomial_size),
            standard.into_data().into_chunks(polynomial_size),
        ) {
            fft.forward_as_torus(
                unsafe { as_mut_uninit(fourier_polynomial) },
                standard_polynomial,
                stack.rb_mut(),
            );
        }
    }

    pub fn fill_with_forward_fourier_scratch(
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        row_count: usize,
        decomposition_level_count: DecompositionLevelCount,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        unused!(
            polynomial_size,
            glwe_dimension,
            row_count,
            decomposition_level_count,
        );
        fft.forward_scratch()
    }
}

/// Returns the required memory for [`external_product`].
pub fn external_product_scratch(
    ggsw_polynomial_size: PolynomialSize,
    ggsw_glwe_dimension: GlweDimension,
    ggsw_row_count: usize,
    ggsw_decomposition_level_count: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    unused!(ggsw_row_count, ggsw_decomposition_level_count);
    let glwe_size = ggsw_glwe_dimension.as_glwe_size();
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<u64>(glwe_size.0 * ggsw_polynomial_size.0, align)?;
    let fourier_scratch =
        StackReq::try_new_aligned::<f64>(glwe_size.0 * ggsw_polynomial_size.0, align)?;
    let fourier_scratch_single = StackReq::try_new_aligned::<f64>(ggsw_polynomial_size.0, align)?;

    let substack3 = fft.forward_scratch()?;
    let substack2 = substack3.try_and(fourier_scratch_single)?;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = StackReq::try_any_of([
        substack1.try_and(standard_scratch)?,
        fft.backward_scratch()?,
    ])?;
    substack0.try_and(fourier_scratch)
}

/// Performs the external product of `ggsw` and `glwe`, and stores the result in `out`.
pub fn external_product(
    mut out: GlweCiphertext<&mut [u64]>,
    ggsw: GgswCiphertext<&[f64]>,
    glwe: GlweCiphertext<&[u64]>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size, glwe.polynomial_size);
    debug_assert_eq!(ggsw.polynomial_size, out.polynomial_size);
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_dimension, glwe.glwe_dimension);
    debug_assert_eq!(ggsw.glwe_dimension, out.glwe_dimension);

    let align = CACHELINE_ALIGN;
    let polynomial_size = ggsw.polynomial_size.0;

    let decomposer =
        SignedDecomposer::new(ggsw.decomposition_base_log, ggsw.decomposition_level_count);

    let (mut output_fft_buffer, mut substack0) = stack.make_aligned_uninit::<f64>(
        polynomial_size * ggsw.glwe_dimension.as_glwe_size().0,
        align,
    );

    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;
    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIter::new(
            glwe.into_data()
                .iter()
                .map(|s| decomposer.closest_representable(*s)),
            DecompositionBaseLog(decomposer.decomposition_base_log),
            DecompositionLevelCount(decomposer.decomposition_level_count),
            substack0.rb_mut(),
        );

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        ggsw.into_level_matrices_iter()
            .rev()
            .for_each(|ggsw_decomposition_matrix| {
                // We retrieve the decomposition of this level.
                let (glwe_level, glwe_decomposition_term, mut substack2) =
                    collect_next_term(&mut decomposition, &mut substack1, align);
                let glwe_decomposition_term = GlweCiphertext::new(
                    &*glwe_decomposition_term,
                    ggsw.polynomial_size,
                    ggsw.glwe_dimension,
                );
                debug_assert_eq!(ggsw_decomposition_matrix.decomposition_level, glwe_level);

                // For each level we have to add the result of the vector-matrix product between the
                // decomposition of the glwe, and the ggsw level matrix to the output. To do so, we
                // iteratively add to the output, the product between every line of the matrix, and
                // the corresponding (scalar) polynomial in the glwe decomposition:
                //
                //                ggsw_mat                        ggsw_mat
                //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
                //  | - - - | x | - - - - |         | - - - | x | - - - - | <
                //    ^         | - - - - |             ^       | - - - - |
                //
                //        t = 1                           t = 2                     ...
                izip!(
                    ggsw_decomposition_matrix.into_rows_iter(),
                    glwe_decomposition_term
                        .into_data()
                        .into_chunks(polynomial_size)
                )
                .for_each(|(ggsw_row, glwe_poly)| {
                    let (mut fourier, substack3) = substack2
                        .rb_mut()
                        .make_aligned_uninit::<f64>(polynomial_size, align);
                    // We perform the forward fft transform for the glwe polynomial
                    fft.forward_as_integer(&mut fourier, glwe_poly, substack3);
                    let fourier = unsafe { assume_init_mut(&mut fourier) };
                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.

                    // SAFETY: see comment above definition of `output_fft_buffer`
                    unsafe {
                        update_with_fmadd(
                            output_fft_buffer,
                            ggsw_row,
                            fourier,
                            is_output_uninit,
                            polynomial_size,
                        )
                    };

                    // we initialized `output_fft_buffer, so we can set this to false
                    is_output_uninit = false;
                });
            });
    }

    // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
    // In this section, we bring the result from the fourier domain, back to the standard
    // domain, and add it to the output.
    //
    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        // SAFETY: output_fft_buffer is initialized, since `is_output_uninit` is false
        let output_fft_buffer = &*unsafe { assume_init_mut(output_fft_buffer) };
        izip!(
            out.as_mut_view().into_data().into_chunks(polynomial_size),
            output_fft_buffer.into_chunks(polynomial_size),
        )
        .for_each(|(out, fourier)| {
            fft.add_backward_as_torus(out, fourier, substack0.rb_mut());
        });
    }
}

#[cfg_attr(__profiling, inline(never))]
fn collect_next_term<'a>(
    decomposition: &mut TensorSignedDecompositionLendingIter<'_>,
    substack1: &'a mut DynStack,
    align: usize,
) -> (DecompositionLevel, DynArray<'a, u64>, DynStack<'a>) {
    let (glwe_level, _, glwe_decomposition_term) = decomposition.next_term().unwrap();
    let (glwe_decomposition_term, substack2) = substack1
        .rb_mut()
        .collect_aligned(align, glwe_decomposition_term);
    (glwe_level, glwe_decomposition_term, substack2)
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86 {
    use crate::implementation::convert::x86::*;
    use core::mem::MaybeUninit;
    use pulp::{as_arrays, as_arrays_mut};

    /// # Postconditions
    ///
    /// this function leaves all the elements of `output_fourier` in an initialized state.
    ///
    /// # Safety
    ///
    ///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
    #[cfg(feature = "nightly")]
    unsafe fn update_with_fmadd_avx512(
        simd: Avx512,
        output_fourier: &mut [MaybeUninit<f64>],
        ggsw_polynomial: &[f64],
        fourier: &[f64],
        is_output_uninit: bool,
    ) {
        use crate::implementation::assume_init_mut;

        let n = output_fourier.len();

        debug_assert_eq!(n, ggsw_polynomial.len());
        debug_assert_eq!(n, fourier.len());
        debug_assert_eq!(n % 8, 0);

        // 8×f64 => 4×c64
        let (ggsw_polynomial, _) = as_arrays::<8, _>(ggsw_polynomial);
        let (fourier, _) = as_arrays::<8, _>(fourier);

        simd.vectorize(|| {
            let simd = simd.avx512f;
            if is_output_uninit {
                let (output_fourier, _) = as_arrays_mut::<8, _>(output_fourier);
                for (out, lhs, rhs) in izip!(output_fourier, ggsw_polynomial, fourier) {
                    let ab = simd_cast(*lhs);
                    let xy = simd_cast(*rhs);
                    let aa = simd._mm512_unpacklo_pd(ab, ab);
                    let bb = simd._mm512_unpackhi_pd(ab, ab);
                    let yx = simd._mm512_permute_pd::<0b01010101>(xy);
                    *out = simd_cast(simd._mm512_fmaddsub_pd(aa, xy, simd._mm512_mul_pd(bb, yx)));
                }
            } else {
                let (output_fourier, _) =
                    as_arrays_mut::<8, _>(unsafe { assume_init_mut(output_fourier) });
                for (out, lhs, rhs) in izip!(output_fourier, ggsw_polynomial, fourier) {
                    let ab = simd_cast(*lhs);
                    let xy = simd_cast(*rhs);
                    let aa = simd._mm512_unpacklo_pd(ab, ab);
                    let bb = simd._mm512_unpackhi_pd(ab, ab);
                    let yx = simd._mm512_permute_pd::<0b01010101>(xy);
                    *out = simd_cast(simd._mm512_fmaddsub_pd(
                        aa,
                        xy,
                        simd._mm512_fmaddsub_pd(bb, yx, simd_cast(*out)),
                    ));
                }
            }
        });
    }

    /// # Postconditions
    ///
    /// this function leaves all the elements of `output_fourier` in an initialized state.
    ///
    /// # Safety
    ///
    ///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
    unsafe fn update_with_fmadd_fma(
        simd: FusedMulAdd,
        output_fourier: &mut [MaybeUninit<f64>],
        ggsw_polynomial: &[f64],
        fourier: &[f64],
        is_output_uninit: bool,
    ) {
        use crate::implementation::assume_init_mut;

        let n = output_fourier.len();

        debug_assert_eq!(n, ggsw_polynomial.len());
        debug_assert_eq!(n, fourier.len());
        debug_assert_eq!(n % 4, 0);

        // 8×f64 => 4×c64
        let (ggsw_polynomial, _) = as_arrays::<4, _>(ggsw_polynomial);
        let (fourier, _) = as_arrays::<4, _>(fourier);

        simd.vectorize(|| {
            let FusedMulAdd { avx, fma, .. } = simd;
            if is_output_uninit {
                let (output_fourier, _) = as_arrays_mut::<4, _>(output_fourier);
                for (out, lhs, rhs) in izip!(output_fourier, ggsw_polynomial, fourier) {
                    let ab = simd_cast(*lhs);
                    let xy = simd_cast(*rhs);
                    let aa = avx._mm256_unpacklo_pd(ab, ab);
                    let bb = avx._mm256_unpackhi_pd(ab, ab);
                    let yx = avx._mm256_permute_pd::<0b0101>(xy);
                    *out = simd_cast(fma._mm256_fmaddsub_pd(aa, xy, avx._mm256_mul_pd(bb, yx)));
                }
            } else {
                let (output_fourier, _) =
                    as_arrays_mut::<4, _>(unsafe { assume_init_mut(output_fourier) });
                for (out, lhs, rhs) in izip!(output_fourier, ggsw_polynomial, fourier) {
                    let ab = simd_cast(*lhs);
                    let xy = simd_cast(*rhs);
                    let aa = avx._mm256_unpacklo_pd(ab, ab);
                    let bb = avx._mm256_unpackhi_pd(ab, ab);
                    let yx = avx._mm256_permute_pd::<0b0101>(xy);
                    *out = simd_cast(fma._mm256_fmaddsub_pd(
                        aa,
                        xy,
                        fma._mm256_fmaddsub_pd(bb, yx, simd_cast(*out)),
                    ));
                }
            }
        });
    }

    pub unsafe fn update_with_fmadd(
        output_fourier: &mut [MaybeUninit<f64>],
        ggsw_polynomial: &[f64],
        fourier: &[f64],
        is_output_uninit: bool,
    ) {
        #[cfg(feature = "nightly")]
        if let Some(simd) = Avx512::try_new() {
            return unsafe {
                update_with_fmadd_avx512(
                    simd,
                    output_fourier,
                    ggsw_polynomial,
                    fourier,
                    is_output_uninit,
                )
            };
        }
        if let Some(simd) = FusedMulAdd::try_new() {
            return unsafe {
                update_with_fmadd_fma(
                    simd,
                    output_fourier,
                    ggsw_polynomial,
                    fourier,
                    is_output_uninit,
                )
            };
        }

        unsafe {
            super::update_with_fmadd_scalar(
                output_fourier,
                ggsw_polynomial,
                fourier,
                is_output_uninit,
            )
        }
    }
}

/// # Postconditions
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
///
/// # Safety
///
///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
unsafe fn update_with_fmadd_scalar(
    output_fourier: &mut [MaybeUninit<f64>],
    ggsw_polynomial: &[f64],
    fourier: &[f64],
    is_output_uninit: bool,
) {
    let (output_fourier, _) = as_arrays_mut::<2, _>(output_fourier);
    let (ggsw_polynomial, _) = as_arrays::<2, _>(ggsw_polynomial);
    let (fourier, _) = as_arrays::<2, _>(fourier);

    if is_output_uninit {
        // we're writing to output_fft_buffer for the first time
        // so its contents are uninitialized
        izip!(output_fourier, ggsw_polynomial, fourier).for_each(|(out_fourier, lhs, rhs)| {
            let lhs = c64::new(lhs[0], lhs[1]);
            let rhs = c64::new(rhs[0], rhs[1]);
            let result = lhs * rhs;
            out_fourier[0].write(result.re);
            out_fourier[1].write(result.im);
        });
    } else {
        // we already wrote to output_fft_buffer, so we can assume its contents are
        // initialized.
        izip!(output_fourier, ggsw_polynomial, fourier).for_each(|(out_fourier, lhs, rhs)| {
            let lhs = c64::new(lhs[0], lhs[1]);
            let rhs = c64::new(rhs[0], rhs[1]);
            let result = lhs * rhs;
            *unsafe { out_fourier[0].assume_init_mut() } += result.re;
            *unsafe { out_fourier[1].assume_init_mut() } += result.im;
        });
    }
}

/// # Postconditions
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
///
/// # Safety
///
///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
#[cfg_attr(__profiling, inline(never))]
unsafe fn update_with_fmadd(
    output_fft_buffer: &mut [MaybeUninit<f64>],
    ggsw_row: GgswLevelRow<&[f64]>,
    fourier: &[f64],
    is_output_uninit: bool,
    polynomial_size: usize,
) {
    izip!(
        output_fft_buffer.into_chunks(polynomial_size),
        ggsw_row.data.into_chunks(polynomial_size),
    )
    .for_each(|(output_fourier, ggsw_poly)| unsafe {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        x86::update_with_fmadd(output_fourier, ggsw_poly, fourier, is_output_uninit);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        update_with_fmadd_scalar(output_fourier, ggsw_poly, fourier, is_output_uninit);
    });
}
