//! Primitives for the so-called Wop-PBS (Without Padding Programmable Bootstrapping)

use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::math::fft::{AlignedVec, Complex64};
use crate::commons::crypto::encoding::Cleartext;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::parameters::{CiphertextCount, DeltaLog, ExtractedBitsCount, LweDimension};

#[cfg(test)]
mod test;

/// Function to extract `number_of_bits_to_extract` from an [`LweCiphertext`] starting at the bit
/// number `delta_log` (0-indexed) included.
///
/// Ouput bits are ordered from the MSB to the LSB. Each one of them is output in a distinct LWE
/// ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most significant bit
/// in the plaintext representation).
pub fn extract_bits<Scalar>(
    delta_log: DeltaLog,
    lwe_in: &LweCiphertext<Vec<Scalar>>,
    ksk: &LweKeyswitchKey<Vec<Scalar>>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
    number_of_bits_to_extract: ExtractedBitsCount,
) -> LweList<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
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

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let lwe_in_size = lwe_in.lwe_size();

    // The clone here is needed as we subtract extracted bits as we go from the original ciphertext
    let mut lwe_in_buffer = lwe_in.clone();
    let mut lwe_bit_left_shift_buffer = LweCiphertext::allocate(Scalar::ZERO, lwe_in_size);
    let mut lwe_out_ks_buffer = LweCiphertext::allocate(Scalar::ZERO, ksk.lwe_size());
    let mut pbs_accumulator = GlweCiphertext::allocate(Scalar::ZERO, polynomial_size, glwe_size);
    let mut lwe_out_pbs_buffer = LweCiphertext::allocate(
        Scalar::ZERO,
        LweDimension(glwe_dimension.0 * polynomial_size.0).to_lwe_size(),
    );

    // Output List
    let mut output_lwe_list = LweList::allocate(
        Scalar::ZERO,
        ksk.lwe_size(),
        CiphertextCount(number_of_bits_to_extract),
    );

    // We iterate on the list in reverse as we want to store the extracted MSB at index 0
    for (bit_idx, mut output_ct) in output_lwe_list.ciphertext_iter_mut().rev().enumerate() {
        // Shift on padding bit
        lwe_bit_left_shift_buffer.fill_with_scalar_mul(
            &lwe_in_buffer,
            &Cleartext(Scalar::ONE << (ciphertext_n_bits - delta_log.0 - bit_idx - 1)),
        );

        // Key switch to input PBS key
        ksk.keyswitch_ciphertext(&mut lwe_out_ks_buffer, &lwe_bit_left_shift_buffer);
        // Store the keyswitch output unmodified to the output list (as we need to to do other
        // computations on the output of the keyswitch)
        output_ct
            .as_mut_tensor()
            .fill_with_copy(lwe_out_ks_buffer.as_tensor());

        // If this was the last extracted bit break
        // -1 because if the number_of_bits_to_extract is 1 we want to stop right away
        if bit_idx == number_of_bits_to_extract - 1 {
            break;
        }

        // Add q/4 to center the error while computing a negacyclic LUT
        let out_ks_body = lwe_out_ks_buffer.get_mut_body();
        out_ks_body.0 = out_ks_body
            .0
            .wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

        // Fill lut for the current bit (equivalent to trivial encryption as mask is 0s)
        // The LUT is filled with -alpha in each coefficient where alpha = delta*2^{bit_idx-1}
        for poly_coeff in pbs_accumulator
            .get_mut_body()
            .as_mut_polynomial()
            .coefficient_iter_mut()
        {
            *poly_coeff = Scalar::ZERO.wrapping_sub(Scalar::ONE << (delta_log.0 - 1 + bit_idx));
        }

        // Applying a negacyclic LUT on a ciphertext with one bit of message in the MSB and no bit
        // of padding
        fourier_bsk.bootstrap(
            &mut lwe_out_pbs_buffer,
            &lwe_out_ks_buffer,
            &pbs_accumulator,
            buffers,
        );

        // Add alpha where alpha = delta*2^{bit_idx-1} to end up with an encryption of 0 if the
        // extracted bit was 0 and 1 in the other case
        let out_pbs_body = lwe_out_pbs_buffer.get_mut_body();
        out_pbs_body.0 = out_pbs_body
            .0
            .wrapping_add(Scalar::ONE << (delta_log.0 - 1 + bit_idx));

        // Remove the extracted bit from the initial LWE to get a 0 at the extracted bit location.
        lwe_in_buffer.update_with_sub(&lwe_out_pbs_buffer);
    }

    output_lwe_list
}
