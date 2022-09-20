use dyn_stack::{DynStack, ReborrowMut, SizeOverflow, StackReq};

use super::super::math::fft::FftView;
use super::bootstrap::{bootstrap_scratch, FourierLweBootstrapKeyView};
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::CastInto;
use crate::commons::utils::izip;
#[allow(deprecated)]
use crate::prelude::{
    DeltaLog, ExtractedBitsCount, GlweSize, LweDimension, LweSize, PolynomialSize,
};

pub fn extract_bits_scratch<Scalar>(
    lwe_dimension: LweDimension,
    ksk_after_key_size: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = aligned_vec::CACHELINE_ALIGN;

    let lwe_in_buffer = StackReq::try_new_aligned::<Scalar>(lwe_dimension.to_lwe_size().0, align)?;
    let lwe_out_ks_buffer =
        StackReq::try_new_aligned::<Scalar>(ksk_after_key_size.to_lwe_size().0, align)?;
    let pbs_accumulator =
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, align)?;
    let lwe_out_pbs_buffer = StackReq::try_new_aligned::<Scalar>(
        glwe_size.to_glwe_dimension().0 * polynomial_size.0 + 1,
        align,
    )?;
    let lwe_bit_left_shift_buffer = lwe_in_buffer;
    let bootstrap_scratch = bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft)?;

    lwe_in_buffer
        .try_and(lwe_out_ks_buffer)?
        .try_and(pbs_accumulator)?
        .try_and(lwe_out_pbs_buffer)?
        .try_and(StackReq::try_any_of([
            lwe_bit_left_shift_buffer,
            bootstrap_scratch,
        ])?)
}

/// Function to extract `number_of_bits_to_extract` from an [`LweCiphertext`] starting at the bit
/// number `delta_log` (0-indexed) included.
///
/// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct LWE
/// ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most significant bit
/// in the plaintext representation).
#[allow(clippy::too_many_arguments)]
pub fn extract_bits<Scalar: UnsignedTorus + CastInto<usize>>(
    mut lwe_list_out: LweList<&'_ mut [Scalar]>,
    lwe_in: LweCiphertext<&'_ [Scalar]>,
    ksk: LweKeyswitchKey<&'_ [Scalar]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    let ciphertext_n_bits = Scalar::BITS;
    let number_of_bits_to_extract = number_of_bits_to_extract.0;

    debug_assert!(
        ciphertext_n_bits >= number_of_bits_to_extract + delta_log.0,
        "Tried to extract {} bits, while the maximum number of extractable bits for {} bits
        ciphertexts and a scaling factor of 2^{} is {}",
        number_of_bits_to_extract,
        ciphertext_n_bits,
        delta_log.0,
        ciphertext_n_bits - delta_log.0,
    );
    debug_assert!(
        lwe_list_out.lwe_size().to_lwe_dimension() == ksk.after_key_size(),
        "lwe_list_out needs to have an lwe_size of {}, got {}",
        ksk.after_key_size().0,
        lwe_list_out.lwe_size().to_lwe_dimension().0,
    );
    debug_assert!(
        lwe_list_out.count().0 == number_of_bits_to_extract,
        "lwe_list_out needs to have a ciphertext count of {}, got {}",
        number_of_bits_to_extract,
        lwe_list_out.count().0,
    );
    debug_assert!(
        lwe_in.lwe_size() == fourier_bsk.output_lwe_dimension().to_lwe_size(),
        "lwe_in needs to have an LWE dimension of {}, got {}",
        fourier_bsk.output_lwe_dimension().to_lwe_size().0,
        lwe_in.lwe_size().0,
    );
    debug_assert!(
        ksk.after_key_size() == fourier_bsk.key_size(),
        "ksk needs to have an output LWE dimension of {}, got {}",
        fourier_bsk.key_size().0,
        ksk.after_key_size().0,
    );

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();

    let align = aligned_vec::CACHELINE_ALIGN;

    let (mut lwe_in_buffer_data, stack) =
        stack.collect_aligned(align, lwe_in.into_container().iter().copied());
    let mut lwe_in_buffer = LweCiphertext::from_container(&mut *lwe_in_buffer_data);

    let (mut lwe_out_ks_buffer_data, stack) =
        stack.make_aligned_with(ksk.lwe_size().0, align, |_| Scalar::ZERO);
    let mut lwe_out_ks_buffer = LweCiphertext::from_container(&mut *lwe_out_ks_buffer_data);

    let (mut pbs_accumulator_data, stack) =
        stack.make_aligned_with(glwe_size.0 * polynomial_size.0, align, |_| Scalar::ZERO);
    let mut pbs_accumulator =
        GlweCiphertext::from_container(&mut *pbs_accumulator_data, polynomial_size);

    let lwe_size = LweSize(glwe_dimension.0 * polynomial_size.0 + 1);
    let (mut lwe_out_pbs_buffer_data, mut stack) =
        stack.make_aligned_with(lwe_size.0, align, |_| Scalar::ZERO);
    let mut lwe_out_pbs_buffer = LweCiphertext::from_container(&mut *lwe_out_pbs_buffer_data);

    // We iterate on the list in reverse as we want to store the extracted MSB at index 0
    for (bit_idx, output_ct) in lwe_list_out.ciphertext_iter_mut().rev().enumerate() {
        // Shift on padding bit
        let (lwe_bit_left_shift_buffer_data, _) = stack.rb_mut().collect_aligned(
            align,
            lwe_in_buffer
                .as_view()
                .into_container()
                .iter()
                .map(|s| *s << (ciphertext_n_bits - delta_log.0 - bit_idx - 1)),
        );

        // Key switch to input PBS key
        ksk.keyswitch_ciphertext(
            &mut lwe_out_ks_buffer.as_mut_view(),
            &LweCiphertext::from_container(&*lwe_bit_left_shift_buffer_data),
        );

        drop(lwe_bit_left_shift_buffer_data);

        // Store the keyswitch output unmodified to the output list (as we need to to do other
        // computations on the output of the keyswitch)
        output_ct
            .into_container()
            .copy_from_slice(lwe_out_ks_buffer.as_view().into_container());

        // If this was the last extracted bit, break
        // we subtract 1 because if the number_of_bits_to_extract is 1 we want to stop right away
        if bit_idx == number_of_bits_to_extract - 1 {
            break;
        }

        // Add q/4 to center the error while computing a negacyclic LUT
        let out_ks_body = &mut lwe_out_ks_buffer.get_mut_body().0;
        *out_ks_body = out_ks_body.wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

        // Fill lut for the current bit (equivalent to trivial encryption as mask is 0s)
        // The LUT is filled with -alpha in each coefficient where alpha = delta*2^{bit_idx-1}
        for poly_coeff in &mut pbs_accumulator
            .as_mut_view()
            .get_mut_body()
            .into_polynomial()
            .coefficient_iter_mut()
        {
            *poly_coeff = Scalar::ZERO.wrapping_sub(Scalar::ONE << (delta_log.0 - 1 + bit_idx));
        }

        fourier_bsk.bootstrap(
            lwe_out_pbs_buffer.as_mut_view().into_container(),
            lwe_out_ks_buffer.as_view().into_container(),
            pbs_accumulator.as_view(),
            fft,
            stack.rb_mut(),
        );

        // Add alpha where alpha = delta*2^{bit_idx-1} to end up with an encryption of 0 if the
        // extracted bit was 0 and 1 in the other case
        let out_pbs_body = &mut lwe_out_pbs_buffer.get_mut_body().0;

        *out_pbs_body = out_pbs_body.wrapping_add(Scalar::ONE << (delta_log.0 + bit_idx - 1));

        // Remove the extracted bit from the initial LWE to get a 0 at the extracted bit location.
        izip!(
            lwe_in_buffer.as_mut_view().into_container(),
            lwe_out_pbs_buffer.as_view().into_container()
        )
        .for_each(|(out, inp)| *out = out.wrapping_sub(*inp));
    }
}

#[cfg(test)]
mod tests;
