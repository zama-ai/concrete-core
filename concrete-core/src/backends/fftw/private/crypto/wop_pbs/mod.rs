//! Primitives for the so-called Wop-PBS (Without Padding Programmable Bootstrapping)

use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::math::fft::Complex64;
use crate::commons::crypto::encoding::Cleartext;
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::{GlweCiphertext, PrivateFunctionalPackingKeyswitchKeyList};
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::math::tensor::{AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount, LweDimension,
};

#[cfg(test)]
mod test;

/// Function to extract `number_of_bits_to_extract` from an [`LweCiphertext`] starting at the bit
/// number `delta_log` (0-indexed) included.
///
/// Ouput bits are ordered from the MSB to the LSB. Each one of them is output in a distinct LWE
/// ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most significant bit
/// in the plaintext representation).
pub fn extract_bits<Scalar, C1>(
    delta_log: DeltaLog,
    lwe_list_out: &mut LweList<Vec<Scalar>>,
    lwe_in: &LweCiphertext<Vec<Scalar>>,
    ksk: &LweKeyswitchKey<Vec<Scalar>>,
    fourier_bsk: &FourierBootstrapKey<C1, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
    number_of_bits_to_extract: ExtractedBitsCount,
) where
    Scalar: UnsignedTorus,
    FourierBootstrapKey<C1, Scalar>: AsRefTensor<Element = Complex64>,
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
    debug_assert!(
        lwe_list_out.lwe_size() == ksk.lwe_size(),
        "lwe_list_out needs to have an lwe_size of {}, got {}",
        ksk.lwe_size().0,
        lwe_list_out.lwe_size().0,
    );
    debug_assert!(
        lwe_list_out.count().0 == number_of_bits_to_extract,
        "lwe_list_out needs to have a ciphertext count of {}, got {}",
        number_of_bits_to_extract,
        lwe_list_out.count().0,
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

    // We iterate on the list in reverse as we want to store the extracted MSB at index 0
    for (bit_idx, mut output_ct) in lwe_list_out.ciphertext_iter_mut().rev().enumerate() {
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
}

/// Circuit bootstrapping for binary messages, i.e. containing only one bit of message
///
/// The output GGSW ciphertext `ggsw_out` decomposition base log and level count are used as the
/// circuit_bootstrap_binary decomposition base log and level count.
pub fn circuit_bootstrap_binary<Scalar, C1, C2, C3, C4>(
    fourier_bsk: &FourierBootstrapKey<C1, Scalar>,
    lwe_in: &LweCiphertext<C2>,
    ggsw_out: &mut StandardGgswCiphertext<C3>,
    buffers: &mut FourierBuffers<Scalar>,
    delta_log: DeltaLog,
    fpksk_list: &PrivateFunctionalPackingKeyswitchKeyList<C4>,
) where
    Scalar: UnsignedTorus,
    FourierBootstrapKey<C1, Scalar>: AsRefTensor<Element = Complex64>,
    C2: AsRefSlice<Element = Scalar>,
    StandardGgswCiphertext<C3>: AsMutTensor<Element = Scalar>,
    PrivateFunctionalPackingKeyswitchKeyList<C4>: AsRefTensor<Element = Scalar>,
{
    let level_cbs = ggsw_out.decomposition_level_count();
    let base_log_cbs = ggsw_out.decomposition_base_log();

    debug_assert!(
        level_cbs.0 >= 1,
        "level_cbs needs to be >= 1, got {}",
        level_cbs.0
    );
    debug_assert!(
        base_log_cbs.0 >= 1,
        "base_log_cbs needs to be >= 1, got {}",
        base_log_cbs.0
    );

    let bsk_glwe_dimension = fourier_bsk.glwe_size().to_glwe_dimension();
    let bsk_polynomial_size = fourier_bsk.polynomial_size();

    let fpksk_input_lwe_key_dimension = fpksk_list.input_lwe_key_dimension();

    debug_assert!(
        fpksk_input_lwe_key_dimension.0 == bsk_polynomial_size.0 * bsk_glwe_dimension.0,
        "The fourier_bsk polynomial_size, got {}, must be equal to the fpksk \
        input_lwe_key_dimension, got {}",
        bsk_polynomial_size.0 * bsk_glwe_dimension.0,
        fpksk_input_lwe_key_dimension.0
    );

    let fpksk_output_polynomial_size = fpksk_list.output_polynomial_size();
    let fpksk_output_glwe_key_dimension = fpksk_list.output_glwe_key_dimension();

    debug_assert!(
        ggsw_out.polynomial_size() == fpksk_output_polynomial_size,
        "The output GGSW ciphertext needs to have the same polynomial size as the fpksks, \
        got {}, expeceted {}",
        ggsw_out.polynomial_size().0,
        fpksk_output_polynomial_size.0
    );

    debug_assert!(
        ggsw_out.glwe_size().to_glwe_dimension() == fpksk_output_glwe_key_dimension,
        "The output GGSW ciphertext needs to have the same GLWE dimension as the fpksks, \
        got {}, expeceted {}",
        ggsw_out.glwe_size().to_glwe_dimension().0,
        fpksk_output_glwe_key_dimension.0
    );

    debug_assert!(
        ggsw_out.glwe_size().0 * ggsw_out.decomposition_level_count().0
            == fpksk_list.fpksk_count().0,
        "The input vector of fpksk needs to have {} (ggsw.glwe_size * \
        ggsw.decomposition_level_count) elements got {}",
        ggsw_out.glwe_size().0 * ggsw_out.decomposition_level_count().0,
        fpksk_list.fpksk_count().0,
    );

    // Output for every bootstrapping
    let mut lwe_out_bs_buffer: LweCiphertext<Vec<Scalar>> = LweCiphertext::allocate(
        Scalar::ZERO,
        LweDimension(bsk_glwe_dimension.0 * bsk_polynomial_size.0).to_lwe_size(),
    );
    // Output for every pfksk that that come from the output GGSW
    let mut glwe_out_pfksk_buffer = ggsw_out.as_mut_glwe_list();

    let mut out_pfksk_buffer_iter = glwe_out_pfksk_buffer.ciphertext_iter_mut();

    for level_idx in 0..level_cbs.0 {
        homomorphic_shift_binary(
            fourier_bsk,
            &mut lwe_out_bs_buffer,
            lwe_in,
            buffers,
            DecompositionLevelCount(level_idx + 1),
            base_log_cbs,
            delta_log,
        );

        for pfksk in fpksk_list.fpksk_iter() {
            let mut glwe_out = out_pfksk_buffer_iter.next().unwrap();
            pfksk.private_functional_keyswitch_ciphertext(&mut glwe_out, &lwe_out_bs_buffer);
        }
    }
}

/// Homomorphic shift for LWE without padding bit
///
/// Starts by shifting the message bit at bit #delta_log to the padding bit and then shifts it to
/// the right by base_log * level.
pub fn homomorphic_shift_binary<Scalar, C1, C2, C3>(
    fourier_bsk: &FourierBootstrapKey<C1, Scalar>,
    lwe_out: &mut LweCiphertext<C2>,
    lwe_in: &LweCiphertext<C3>,
    buffers: &mut FourierBuffers<Scalar>,
    level_count_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
) where
    Scalar: UnsignedTorus,
    FourierBootstrapKey<C1, Scalar>: AsRefTensor<Element = Complex64>,
    LweCiphertext<C2>: AsMutTensor<Element = Scalar>,
    LweCiphertext<C3>: AsRefTensor<Element = Scalar>,
{
    let ciphertext_n_bits = Scalar::BITS;
    let lwe_in_size = lwe_in.lwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();

    let mut lwe_left_shift_buffer = LweCiphertext::allocate(Scalar::ZERO, lwe_in_size);
    // Shift message LSB on padding bit, at this point we expect to have messages with only 1 bit
    // of information
    lwe_left_shift_buffer.fill_with_scalar_mul(
        lwe_in,
        &Cleartext(Scalar::ONE << (ciphertext_n_bits - delta_log.0 - 1)),
    );

    // Add q/4 to center the error while computing a negacyclic LUT
    let mut shift_buffer_body = lwe_left_shift_buffer.get_mut_body();
    shift_buffer_body.0 = shift_buffer_body
        .0
        .wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

    let mut pbs_accumulator =
        GlweCiphertext::allocate(Scalar::ZERO, polynomial_size, fourier_bsk.glwe_size());

    // Fill lut (equivalent to trivial encryption as mask is 0s)
    // The LUT is filled with -alpha in each coefficient where
    // alpha = 2^{log(q) - 1 - base_log * level}
    for poly_coeff in pbs_accumulator
        .get_mut_body()
        .as_mut_polynomial()
        .coefficient_iter_mut()
    {
        *poly_coeff = Scalar::ZERO.wrapping_sub(
            Scalar::ONE << (ciphertext_n_bits - 1 - base_log_cbs.0 * level_count_cbs.0),
        );
    }

    // Applying a negacyclic LUT on a ciphertext with one bit of message in the MSB and no bit
    // of padding
    fourier_bsk.bootstrap(lwe_out, &lwe_left_shift_buffer, &pbs_accumulator, buffers);

    // Add alpha where alpha = 2^{log(q) - 1 - base_log * level}
    // To end up with an encryption of 0 if the message bit was 0 and 1 in the other case
    let out_body = lwe_out.get_mut_body();
    out_body.0 = out_body
        .0
        .wrapping_add(Scalar::ONE << (ciphertext_n_bits - 1 - base_log_cbs.0 * level_count_cbs.0));
}
