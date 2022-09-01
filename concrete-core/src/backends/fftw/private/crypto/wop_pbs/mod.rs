//! Primitives for the so-called Wop-PBS (Without Padding Programmable Bootstrapping)

use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::commons::crypto::encoding::Cleartext;
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::{GlweCiphertext, LwePrivateFunctionalPackingKeyswitchKeyList};
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::math::polynomial::PolynomialList;
use crate::commons::math::tensor::{ck_dim_div, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount, GlweDimension,
    LweDimension, MonomialDegree, PolynomialCount,
};

#[cfg(test)]
mod test;

/// Function to extract `number_of_bits_to_extract` from an [`LweCiphertext`] starting at the bit
/// number `delta_log` (0-indexed) included.
///
/// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct LWE
/// ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most significant bit
/// in the plaintext representation).
pub fn extract_bits<Scalar, C1, C2, C3, C4>(
    delta_log: DeltaLog,
    lwe_list_out: &mut LweList<C1>,
    lwe_in: &LweCiphertext<C2>,
    ksk: &LweKeyswitchKey<C3>,
    fourier_bsk: &FourierBootstrapKey<C4, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
    number_of_bits_to_extract: ExtractedBitsCount,
) where
    Scalar: UnsignedTorus,
    C1: AsMutSlice<Element = Scalar>,
    C2: AsRefSlice<Element = Scalar>,
    C3: AsRefSlice<Element = Scalar>,
    C4: AsRefSlice<Element = Complex64>,
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
    let lwe_in_size = lwe_in.lwe_size();

    // The clone here is needed as we subtract extracted bits as we go from the original ciphertext
    let mut lwe_in_buffer = LweCiphertext::from_container(lwe_in.as_tensor().as_slice().to_vec());
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
    fpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<C4>,
) where
    Scalar: UnsignedTorus,
    C1: AsRefSlice<Element = Complex64>,
    C2: AsRefSlice<Element = Scalar>,
    C3: AsMutSlice<Element = Scalar>,
    C4: AsRefSlice<Element = Scalar>,
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
    let mut lwe_out_bs_buffer = LweCiphertext::allocate(
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
    C1: AsRefSlice<Element = Complex64>,
    C2: AsMutSlice<Element = Scalar>,
    C3: AsRefSlice<Element = Scalar>,
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
    pbs_accumulator
        .get_mut_body()
        .as_mut_tensor()
        .fill_with_element(Scalar::ZERO.wrapping_sub(
            Scalar::ONE << (ciphertext_n_bits - 1 - base_log_cbs.0 * level_count_cbs.0),
        ));

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

/// Perform a circuit bootstrap followed by a vertical packing on ciphertexts encrypting binary
/// messages.
///
/// The circuit bootstrapping uses the private functional packing key switch.
///
/// This is supposed to be used only with binary (1 bit of message) LWE ciphertexts.
#[allow(clippy::too_many_arguments)]
pub fn circuit_bootstrap_binary_vertical_packing<Scalar, C1, C2, C3, C4, C5>(
    big_lut_as_polynomial_list: &PolynomialList<C1>,
    buffers: &mut FourierBuffers<Scalar>,
    fourier_bsk: &FourierBootstrapKey<C2, Scalar>,
    lwe_list_out: &mut LweList<C3>,
    lwe_list_in: &LweList<C4>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<C5>,
) where
    Scalar: UnsignedTorus,
    C1: AsRefSlice<Element = Scalar>,
    C2: AsRefSlice<Element = Complex64>,
    C3: AsMutSlice<Element = Scalar>,
    C4: AsRefSlice<Element = Scalar>,
    C5: AsRefSlice<Element = Scalar>,
{
    debug_assert!(lwe_list_in.count().0 != 0, "Got empty `lwe_list_in`");
    debug_assert!(
        lwe_list_out.lwe_size().to_lwe_dimension().0
            == fourier_bsk.polynomial_size().0 * fourier_bsk.glwe_size().to_glwe_dimension().0,
        "Output LWE ciphertext needs to have an LweDimension of {}, got {}",
        lwe_list_out.lwe_size().to_lwe_dimension().0,
        fourier_bsk.polynomial_size().0 * fourier_bsk.glwe_size().to_glwe_dimension().0
    );

    // TODO: Currently we need split_at and split_at_mut so can't switch to a list-like struct
    // Update once we have a nice list primitive
    let mut vec_ggsw = vec![
        FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            fourier_bsk.polynomial_size(),
            fourier_bsk.glwe_size(),
            level_cbs,
            base_log_cbs,
        );
        lwe_list_in.count().0
    ];
    let mut ggsw_res = StandardGgswCiphertext::allocate(
        Scalar::ZERO,
        fourier_bsk.polynomial_size(),
        fourier_bsk.glwe_size(),
        level_cbs,
        base_log_cbs,
    );
    for (lwe_in, ggsw) in lwe_list_in.ciphertext_iter().zip(vec_ggsw.iter_mut()) {
        circuit_bootstrap_binary(
            fourier_bsk,
            &lwe_in,
            &mut ggsw_res,
            buffers,
            DeltaLog(Scalar::BITS - 1),
            fpksk_list,
        );
        ggsw.fill_with_forward_fourier(&ggsw_res, buffers);
    }

    // We deduce the number of luts in the vec_lut from the number of cipherxtexts in lwe_list_out
    let number_of_luts = lwe_list_out.count().0;

    ck_dim_div!(big_lut_as_polynomial_list.polynomial_count().0 => number_of_luts);
    let small_lut_size =
        PolynomialCount(big_lut_as_polynomial_list.polynomial_count().0 / number_of_luts);

    for (lut, mut lwe_out) in big_lut_as_polynomial_list
        .sublist_iter(small_lut_size)
        .zip(lwe_list_out.ciphertext_iter_mut())
    {
        vertical_packing(&lut, &mut lwe_out, &vec_ggsw, buffers);
    }
}

// GGSW ciphertexts are stored from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
pub fn vertical_packing<Scalar, C1, C2, C3>(
    lut: &PolynomialList<C1>,
    lwe_out: &mut LweCiphertext<C2>,
    vec_ggsw: &[FourierGgswCiphertext<C3, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
) where
    Scalar: UnsignedTorus,
    C1: AsRefSlice<Element = Scalar>,
    C2: AsMutSlice<Element = Scalar>,
    C3: AsRefSlice<Element = Complex64>,
{
    let polynomial_size = vec_ggsw[0].polynomial_size();
    let glwe_dimension = vec_ggsw[0].glwe_size().to_glwe_dimension();

    debug_assert!(
        lut.polynomial_count().0 == 1 << vec_ggsw.len(),
        "Need {} polynomials in `lut`, got {}",
        1 << vec_ggsw.len(),
        lut.polynomial_count().0
    );

    debug_assert!(
        lwe_out.lwe_size().to_lwe_dimension().0 == polynomial_size.0 * glwe_dimension.0,
        "Output LWE ciphertext needs to have an LweDimension of {}, got {}",
        lwe_out.lwe_size().to_lwe_dimension().0,
        polynomial_size.0 * glwe_dimension.0
    );

    // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // there is one polynomial, the number will be 0
    let log_lut_number: usize =
        Scalar::BITS - 1 - lut.polynomial_count().0.leading_zeros() as usize;

    let log_number_of_luts_for_cmux_tree = if log_lut_number > vec_ggsw.len() {
        // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
        // Blind rotation
        0
    } else {
        log_lut_number
    };

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = vec_ggsw.split_at(log_number_of_luts_for_cmux_tree);
    let mut cmux_tree_lut_res = cmux_tree_memory_optimized(lut, cmux_ggsw, buffers, glwe_dimension);
    blind_rotate(&mut cmux_tree_lut_res, br_ggsw, buffers);

    // sample extract of the RLWE of the Vertical packing
    cmux_tree_lut_res.fill_lwe_with_sample_extraction(lwe_out, MonomialDegree(0));
}

/// Performs a tree of cmux in a way that limits the total allocated memory to avoid issues for
/// bigger trees.
pub fn cmux_tree_memory_optimized<Scalar, C1, C2>(
    lut_per_layer: &PolynomialList<C1>,
    vec_ggsw: &[FourierGgswCiphertext<C2, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
    glwe_dimension: GlweDimension,
) -> GlweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
    C1: AsRefSlice<Element = Scalar>,
    C2: AsRefSlice<Element = Complex64>,
{
    if !vec_ggsw.is_empty() {
        let polynomial_size = vec_ggsw[0].polynomial_size();
        let nb_layer = vec_ggsw.len();

        let empty_glwe =
            GlweCiphertext::allocate(Scalar::ZERO, polynomial_size, glwe_dimension.to_glwe_size());
        let mut result = empty_glwe.clone();

        // TODO: Currently we need split_at and split_at_mut so can't switch to a list-like struct
        // Update once we have a nice list primitive
        //
        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
        let mut t_0 = vec![empty_glwe.clone(); nb_layer];
        let mut t_1 = vec![empty_glwe.clone(); nb_layer];

        let mut cmux_buffer = empty_glwe;

        let mut t_fill = vec![0_usize; nb_layer];

        debug_assert!(lut_per_layer.polynomial_count().0 == 1 << (nb_layer - 1));

        // Returns lut[2 * i] polynomial where i is the iteration index
        let lut_iter_0 = lut_per_layer.polynomial_iter().step_by(2);
        // Returns lut[2 * i + 1] polynomial where i is the iteration index
        let lut_iter_1 = lut_per_layer.polynomial_iter().skip(1).step_by(2);

        for (lut_2_i, lut_2_i_plus_1) in lut_iter_0.zip(lut_iter_1) {
            //load 2 trivial CT with LUT
            t_0[0]
                .get_mut_body()
                .as_mut_tensor()
                .fill_with_copy(lut_2_i.as_tensor());
            t_1[0]
                .get_mut_body()
                .as_mut_tensor()
                .fill_with_copy(lut_2_i_plus_1.as_tensor());

            t_fill[0] = 2;
            for (j, ggsw) in vec_ggsw.iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    if j != nb_layer - 1 {
                        if t_fill[j + 1] == 0 {
                            // Due to rust borrowing rules we have to use split at to get t_0[j] as
                            // an immutable reference and t_0[j+1] as a
                            // mutable refence
                            let (t_0_j, t_0_j_plus_1) = t_0[j..=j + 1].split_at_mut(1);
                            let t_0_j = &t_0_j[0];
                            let t_0_j_plus_1 = &mut t_0_j_plus_1[0];
                            ggsw.discard_cmux(
                                t_0_j, // &t_0[j]
                                &t_1[j],
                                t_0_j_plus_1, // &mut t_0[j + 1]
                                &mut cmux_buffer,
                                buffers,
                            );
                        } else {
                            // Due to rust borrowing rules we have to use split at to get t_1[j] as
                            // an immutable reference and t_1[j+1] as a
                            // mutable refence
                            let (t_1_j, t_1_j_plus_1) = t_1[j..=j + 1].split_at_mut(1);
                            let t_1_j = &t_1_j[0];
                            let t_1_j_plus_1 = &mut t_1_j_plus_1[0];
                            ggsw.discard_cmux(
                                &t_0[j],
                                t_1_j,        // &t_1[j]
                                t_1_j_plus_1, // &mut t_1[j + 1]
                                &mut cmux_buffer,
                                buffers,
                            );
                        }
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;
                    } else {
                        ggsw.discard_cmux(&t_0[j], &t_1[j], &mut result, &mut cmux_buffer, buffers);
                    }
                } else {
                    break;
                }
            }
        }

        result
    } else {
        let mut out_glwe = GlweCiphertext::allocate(
            Scalar::ZERO,
            lut_per_layer.polynomial_size(),
            glwe_dimension.to_glwe_size(),
        );

        let mut out_body = out_glwe.get_mut_body();
        out_body
            .as_mut_tensor()
            .fill_with_copy(lut_per_layer.as_tensor());

        out_glwe
    }
}

pub fn blind_rotate<Scalar, C1, C2>(
    lut: &mut GlweCiphertext<C1>,
    vec_ggsw: &[FourierGgswCiphertext<C2, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
) where
    Scalar: UnsignedTorus,
    C1: AsMutSlice<Element = Scalar>,
    C2: AsRefSlice<Element = Complex64>,
{
    let mut monomial_degree = MonomialDegree(1);
    let mut ct_0 =
        GlweCiphertext::from_container(lut.as_tensor().as_slice().to_vec(), lut.polynomial_size());
    let mut ct_1 = GlweCiphertext::allocate(Scalar::ZERO, ct_0.polynomial_size(), ct_0.size());
    for ggsw in vec_ggsw.iter().rev() {
        ct_1.as_mut_tensor().fill_with_copy(ct_0.as_tensor());

        ct_1.as_mut_polynomial_list()
            .update_with_wrapping_monic_monomial_div(monomial_degree);
        monomial_degree.0 <<= 1;
        ggsw.cmux(
            &mut ct_0,
            &mut ct_1,
            &mut buffers.fft_buffers,
            &mut buffers.rounded_buffer,
        );
    }

    lut.as_mut_tensor().fill_with_copy(ct_0.as_tensor());
}
