#![allow(clippy::too_many_arguments)]

use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{DynStack, ReborrowMut, SizeOverflow, StackReq};

use super::super::math::fft::FftView;
use super::bootstrap::{bootstrap_scratch, FourierLweBootstrapKeyView};
use super::ggsw::{
    cmux, cmux_scratch, external_product, external_product_scratch,
    fill_with_forward_fourier_scratch, FourierGgswCiphertext,
};
use crate::backends::fft::private::math::fft::FourierPolynomialList;
use crate::commons::crypto::encoding::Cleartext;
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::{GlweCiphertext, LwePrivateFunctionalPackingKeyswitchKeyList};
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::math::polynomial::PolynomialList;
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor, Container, Split};
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::CastInto;
use crate::commons::utils::izip;
use crate::prelude::{
    CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount,
    GlweSize, LweDimension, LweSize, MonomialDegree, PolynomialCount, PolynomialSize,
};

use concrete_fft::c64;

pub fn extract_bits_scratch<Scalar>(
    lwe_dimension: LweDimension,
    ksk_after_key_size: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;

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

    let align = CACHELINE_ALIGN;

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

pub fn circuit_bootstrap_boolean_scratch<Scalar>(
    lwe_in_size: LweSize,
    bsk_output_lwe_size: LweSize,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_new_aligned::<Scalar>(bsk_output_lwe_size.0, CACHELINE_ALIGN)?.try_and(
        homomorphic_shift_boolean_scratch::<Scalar>(lwe_in_size, polynomial_size, glwe_size, fft)?,
    )
}

/// Circuit bootstrapping for boolean messages, i.e. containing only one bit of message
///
/// The output GGSW ciphertext `ggsw_out` decomposition base log and level count are used as the
/// circuit_bootstrap_boolean decomposition base log and level count.
pub fn circuit_bootstrap_boolean<Scalar: UnsignedTorus + CastInto<usize>>(
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    lwe_in: LweCiphertext<&[Scalar]>,
    mut ggsw_out: StandardGgswCiphertext<&mut [Scalar]>,
    delta_log: DeltaLog,
    fpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[Scalar]>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
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

    let fpksk_input_lwe_key_dimension = fpksk_list.input_lwe_key_dimension();
    let fourier_bsk_output_lwe_dimension = fourier_bsk.output_lwe_dimension();

    debug_assert!(
        fpksk_input_lwe_key_dimension == fourier_bsk_output_lwe_dimension,
        "The fourier_bsk output_lwe_dimension, got {}, must be equal to the fpksk \
        input_lwe_key_dimension, got {}",
        fourier_bsk_output_lwe_dimension.0,
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
        ggsw_out.glwe_size().0 == fpksk_list.fpksk_count().0,
        "The input vector of fpksk needs to have {} (ggsw.glwe_size * \
        ggsw.decomposition_level_count) elements got {}",
        ggsw_out.glwe_size().0,
        fpksk_list.fpksk_count().0,
    );

    // Output for every bootstrapping
    let (mut lwe_out_bs_buffer_data, mut stack) = stack.make_aligned_with(
        fourier_bsk_output_lwe_dimension.to_lwe_size().0,
        CACHELINE_ALIGN,
        |_| Scalar::ZERO,
    );
    let mut lwe_out_bs_buffer = LweCiphertext::from_container(&mut *lwe_out_bs_buffer_data);

    // Output for every pfksk that that come from the output GGSW
    let mut glwe_out_pfksk_buffer = ggsw_out.as_mut_glwe_list();

    let mut out_pfksk_buffer_iter = glwe_out_pfksk_buffer.ciphertext_iter_mut();

    for decomposition_level in (1..=level_cbs.0).map(DecompositionLevelCount) {
        homomorphic_shift_boolean(
            fourier_bsk,
            lwe_out_bs_buffer.as_mut_view(),
            lwe_in,
            decomposition_level,
            base_log_cbs,
            delta_log,
            fft,
            stack.rb_mut(),
        );

        for pfksk in fpksk_list.fpksk_iter() {
            let mut glwe_out = out_pfksk_buffer_iter.next().unwrap();
            pfksk.private_functional_keyswitch_ciphertext(&mut glwe_out, &lwe_out_bs_buffer);
        }
    }
}

pub fn homomorphic_shift_boolean_scratch<Scalar>(
    lwe_in_size: LweSize,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    StackReq::try_new_aligned::<Scalar>(lwe_in_size.0, align)?
        .try_and(StackReq::try_new_aligned::<Scalar>(
            polynomial_size.0 * glwe_size.0,
            align,
        )?)?
        .try_and(bootstrap_scratch::<Scalar>(
            glwe_size,
            polynomial_size,
            fft,
        )?)
}

/// Homomorphic shift for LWE without padding bit
///
/// Starts by shifting the message bit at bit #delta_log to the padding bit and then shifts it to
/// the right by base_log * level.
pub fn homomorphic_shift_boolean<Scalar: UnsignedTorus + CastInto<usize>>(
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    mut lwe_out: LweCiphertext<&mut [Scalar]>,
    lwe_in: LweCiphertext<&[Scalar]>,
    level_count_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    let ciphertext_n_bits = Scalar::BITS;
    let lwe_in_size = lwe_in.lwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();

    let (mut lwe_left_shift_buffer_data, stack) =
        stack.make_aligned_with(lwe_in_size.0, CACHELINE_ALIGN, |_| Scalar::ZERO);
    let mut lwe_left_shift_buffer = LweCiphertext::from_container(&mut *lwe_left_shift_buffer_data);
    // Shift message LSB on padding bit, at this point we expect to have messages with only 1 bit
    // of information
    lwe_left_shift_buffer.fill_with_scalar_mul(
        &lwe_in,
        &Cleartext(Scalar::ONE << (ciphertext_n_bits - delta_log.0 - 1)),
    );

    // Add q/4 to center the error while computing a negacyclic LUT
    let mut shift_buffer_body = lwe_left_shift_buffer.get_mut_body();
    shift_buffer_body.0 = shift_buffer_body
        .0
        .wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

    let (mut pbs_accumulator_data, stack) = stack.make_aligned_with(
        polynomial_size.0 * fourier_bsk.glwe_size().0,
        CACHELINE_ALIGN,
        |_| Scalar::ZERO,
    );
    let mut pbs_accumulator =
        GlweCiphertext::from_container(&mut *pbs_accumulator_data, polynomial_size);

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
    fourier_bsk.bootstrap(
        lwe_out.as_mut_view().into_container(),
        lwe_left_shift_buffer.as_view().into_container(),
        pbs_accumulator.as_view(),
        fft,
        stack,
    );

    // Add alpha where alpha = 2^{log(q) - 1 - base_log * level}
    // To end up with an encryption of 0 if the message bit was 0 and 1 in the other case
    let out_body = lwe_out.get_mut_body();
    out_body.0 = out_body
        .0
        .wrapping_add(Scalar::ONE << (ciphertext_n_bits - 1 - base_log_cbs.0 * level_count_cbs.0));
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct GlweCiphertextList<C: Container> {
    data: C,
    count: usize,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct FourierGgswCiphertextList<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    count: usize,
    glwe_size: GlweSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
}

pub type FourierGgswCiphertextListView<'a> = FourierGgswCiphertextList<&'a [c64]>;
pub type FourierGgswCiphertextListMutView<'a> = FourierGgswCiphertextList<&'a mut [c64]>;
pub type GlweCiphertextListView<'a, Scalar> = GlweCiphertextList<&'a [Scalar]>;
pub type GlweCiphertextListMutView<'a, Scalar> = GlweCiphertextList<&'a mut [Scalar]>;

impl<C: Container> GlweCiphertextList<C> {
    pub fn new(
        data: C,
        count: usize,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            count * polynomial_size.0 * glwe_size.0,
        );
        Self {
            data,
            count,
            polynomial_size,
            glwe_size,
        }
    }

    pub fn data(self) -> C {
        self.data
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn as_view(&self) -> GlweCiphertextListView<'_, C::Element> {
        GlweCiphertextListView {
            data: self.data.as_ref(),
            count: self.count,
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
        }
    }

    pub fn as_mut_view(&mut self) -> GlweCiphertextListMutView<'_, C::Element>
    where
        C: AsMut<[C::Element]>,
    {
        GlweCiphertextListMutView {
            data: self.data.as_mut(),
            count: self.count,
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
        }
    }

    pub fn into_glwe_iter(self) -> impl DoubleEndedIterator<Item = GlweCiphertext<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.count)
            .map(move |slice| GlweCiphertext::from_container(slice, self.polynomial_size))
    }
}

impl<C: Container<Element = c64>> FourierGgswCiphertextList<C> {
    pub fn new(
        data: C,
        count: usize,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        assert_eq!(
            data.container_len(),
            count * polynomial_size.0 / 2 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            count,
            glwe_size,
            decomposition_level_count,
            decomposition_base_log,
        }
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn as_view(&self) -> FourierGgswCiphertextListView<'_> {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_ref(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierGgswCiphertextListView {
            fourier,
            count: self.count,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierGgswCiphertextListMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_mut(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierGgswCiphertextListMutView {
            fourier,
            count: self.count,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier.data.split_into(self.count).map(move |slice| {
            FourierGgswCiphertext::new(
                slice,
                self.fourier.polynomial_size,
                self.glwe_size,
                self.decomposition_base_log,
                self.decomposition_level_count,
            )
        })
    }

    pub fn split_at(self, mid: usize) -> (Self, Self)
    where
        C: Split,
    {
        let polynomial_size = self.fourier.polynomial_size;
        let glwe_size = self.glwe_size;
        let decomposition_level_count = self.decomposition_level_count;
        let decomposition_base_log = self.decomposition_base_log;

        let (left, right) = self.fourier.data.split_at(
            mid * polynomial_size.0 / 2 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0,
        );
        (
            Self::new(
                left,
                mid,
                polynomial_size,
                glwe_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
            Self::new(
                right,
                self.count - mid,
                polynomial_size,
                glwe_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
        )
    }
}

pub fn cmux_tree_memory_optimized_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    nb_layer: usize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let t_scratch = StackReq::try_new_aligned::<Scalar>(
        polynomial_size.0 * glwe_size.0 * nb_layer,
        CACHELINE_ALIGN,
    )?;

    StackReq::try_all_of([
        t_scratch,                             // t_0
        t_scratch,                             // t_1
        StackReq::try_new::<usize>(nb_layer)?, // t_fill
        t_scratch,                             // diff
        external_product_scratch::<Scalar>(glwe_size, polynomial_size, fft)?,
    ])
}

/// Performs a tree of cmux in a way that limits the total allocated memory to avoid issues for
/// bigger trees.
pub fn cmux_tree_memory_optimized<Scalar: UnsignedTorus + CastInto<usize>>(
    mut output_glwe: GlweCiphertext<&mut [Scalar]>,
    lut_per_layer: PolynomialList<&[Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    debug_assert!(lut_per_layer.polynomial_count().0 == 1 << ggsw_list.count());

    if ggsw_list.count() > 0 {
        let polynomial_size = ggsw_list.polynomial_size();
        let glwe_size = output_glwe.size();
        let nb_layer = ggsw_list.count();

        debug_assert!(stack.can_hold(
            cmux_tree_memory_optimized_scratch::<Scalar>(polynomial_size, glwe_size, nb_layer, fft)
                .unwrap()
        ));

        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
        let (mut t_0_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );
        let (mut t_1_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );

        let mut t_0 =
            GlweCiphertextList::new(t_0_data.as_mut(), nb_layer, polynomial_size, glwe_size);
        let mut t_1 =
            GlweCiphertextList::new(t_1_data.as_mut(), nb_layer, polynomial_size, glwe_size);

        let (mut t_fill, mut stack) = stack.make_with(nb_layer, |_| 0_usize);

        let mut lut_polynomial_iter = lut_per_layer.into_polynomial_iter();
        loop {
            let even = lut_polynomial_iter.next();
            let odd = lut_polynomial_iter.next();

            let (lut_2i, lut_2i_plus_1) = match (even, odd) {
                (Some(even), Some(odd)) => (even, odd),
                _ => break,
            };

            let mut t_iter = izip!(
                t_0.as_mut_view().into_glwe_iter(),
                t_1.as_mut_view().into_glwe_iter(),
            )
            .enumerate();

            let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

            t0_j.get_mut_body()
                .as_mut_tensor()
                .fill_with_copy(lut_2i.as_tensor());

            t1_j.get_mut_body()
                .as_mut_tensor()
                .fill_with_copy(lut_2i_plus_1.as_tensor());

            t_fill[0] = 2;

            for (j, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    let (diff_data, stack) = stack.rb_mut().collect_aligned(
                        CACHELINE_ALIGN,
                        izip!(
                            t1_j.as_view().into_container(),
                            t0_j.as_view().into_container()
                        )
                        .map(|(a, b)| a.wrapping_sub(*b)),
                    );
                    let diff = GlweCiphertext::from_container(&*diff_data, polynomial_size);

                    if j != nb_layer - 1 {
                        let (j_counter_plus_1, (mut t_0_j_plus_1, mut t_1_j_plus_1)) =
                            t_iter.next().unwrap();

                        assert_eq!(j_counter, j);
                        assert_eq!(j_counter_plus_1, j + 1);

                        let mut output = if t_fill[j + 1] == 0 {
                            t_0_j_plus_1.as_mut_view()
                        } else {
                            t_1_j_plus_1.as_mut_view()
                        };

                        output
                            .as_mut_view()
                            .into_container()
                            .copy_from_slice(t0_j.as_view().into_container());
                        external_product(output, ggsw, diff, fft, stack);
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;

                        drop(diff_data);

                        (j_counter, t0_j, t1_j) = (j_counter_plus_1, t_0_j_plus_1, t_1_j_plus_1);
                    } else {
                        let mut output = output_glwe.as_mut_view();
                        output
                            .as_mut_view()
                            .into_container()
                            .copy_from_slice(t0_j.as_view().into_container());
                        external_product(output, ggsw, diff, fft, stack);
                    }
                } else {
                    break;
                }
            }
        }
    } else {
        output_glwe
            .get_mut_mask()
            .as_mut_tensor()
            .fill_with(|| Scalar::ZERO);
        output_glwe
            .get_mut_body()
            .as_mut_tensor()
            .fill_with_copy(lut_per_layer.as_tensor());
    }
}

pub fn circuit_bootstrap_boolean_vertical_packing_scratch<Scalar>(
    lwe_list_in_count: CiphertextCount,
    lwe_list_out_count: CiphertextCount,
    lwe_in_size: LweSize,
    big_lut_polynomial_count: PolynomialCount,
    bsk_output_lwe_size: LweSize,
    fpksk_output_polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    // We deduce the number of luts in the vec_lut from the number of cipherxtexts in lwe_list_out
    let number_of_luts = lwe_list_out_count.0;
    let small_lut_size = PolynomialCount(big_lut_polynomial_count.0 / number_of_luts);

    StackReq::try_all_of([
        StackReq::try_new_aligned::<c64>(
            lwe_list_in_count.0 * fpksk_output_polynomial_size.0 / 2
                * glwe_size.0
                * glwe_size.0
                * level_cbs.0,
            CACHELINE_ALIGN,
        )?,
        StackReq::try_new_aligned::<Scalar>(
            fpksk_output_polynomial_size.0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
            CACHELINE_ALIGN,
        )?,
        StackReq::try_any_of([
            circuit_bootstrap_boolean_scratch::<Scalar>(
                lwe_in_size,
                bsk_output_lwe_size,
                fpksk_output_polynomial_size,
                glwe_size,
                fft,
            )?,
            fill_with_forward_fourier_scratch(fft)?,
            vertical_packing_scratch::<Scalar>(
                glwe_size,
                fpksk_output_polynomial_size,
                small_lut_size,
                lwe_list_in_count.0,
                fft,
            )?,
        ])?,
    ])
}

/// Perform a circuit bootstrap followed by a vertical packing on ciphertexts encrypting boolean
/// messages.
///
/// The circuit bootstrapping uses the private functional packing key switch.
///
/// This is supposed to be used only with boolean (1 bit of message) LWE ciphertexts.
pub fn circuit_bootstrap_boolean_vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
    big_lut_as_polynomial_list: PolynomialList<&[Scalar]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    mut lwe_list_out: LweList<&mut [Scalar]>,
    lwe_list_in: LweList<&[Scalar]>,
    fpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[Scalar]>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    debug_assert!(stack.can_hold(
        circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
            lwe_list_in.count(),
            lwe_list_out.count(),
            lwe_list_in.lwe_size(),
            big_lut_as_polynomial_list.polynomial_count(),
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            fpksk_list.output_polynomial_size(),
            fourier_bsk.glwe_size(),
            level_cbs,
            fft
        )
        .unwrap()
    ));
    debug_assert!(lwe_list_in.count().0 != 0, "Got empty `lwe_list_in`");
    debug_assert!(
        lwe_list_out.lwe_size().to_lwe_dimension() == fourier_bsk.output_lwe_dimension(),
        "Output LWE ciphertext needs to have an LweDimension of {}, got {}",
        lwe_list_out.lwe_size().to_lwe_dimension().0,
        fourier_bsk.output_lwe_dimension().0
    );

    let glwe_size = fpksk_list.output_glwe_key_dimension().to_glwe_size();
    let (mut ggsw_list_data, stack) = stack.make_aligned_with(
        lwe_list_in.count().0 * fpksk_list.output_polynomial_size().0 / 2
            * glwe_size.0
            * glwe_size.0
            * level_cbs.0,
        CACHELINE_ALIGN,
        |_| c64::default(),
    );
    let (mut ggsw_res_data, mut stack) = stack.make_aligned_with(
        fpksk_list.output_polynomial_size().0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
        CACHELINE_ALIGN,
        |_| Scalar::ZERO,
    );

    let mut ggsw_list = FourierGgswCiphertextListMutView::new(
        &mut ggsw_list_data,
        lwe_list_in.count().0,
        fpksk_list.output_polynomial_size(),
        glwe_size,
        base_log_cbs,
        level_cbs,
    );

    let mut ggsw_res = StandardGgswCiphertext::from_container(
        &mut *ggsw_res_data,
        glwe_size,
        fpksk_list.output_polynomial_size(),
        base_log_cbs,
    );

    for (lwe_in, ggsw) in izip!(
        lwe_list_in.ciphertext_iter(),
        ggsw_list.as_mut_view().into_ggsw_iter(),
    ) {
        circuit_bootstrap_boolean(
            fourier_bsk,
            lwe_in,
            ggsw_res.as_mut_view(),
            DeltaLog(Scalar::BITS - 1),
            fpksk_list,
            fft,
            stack.rb_mut(),
        );

        ggsw.fill_with_forward_fourier(ggsw_res.as_view(), fft, stack.rb_mut());
    }

    // We deduce the number of luts in the vec_lut from the number of cipherxtexts in lwe_list_out
    let number_of_luts = lwe_list_out.count().0;

    let small_lut_size =
        PolynomialCount(big_lut_as_polynomial_list.polynomial_count().0 / number_of_luts);

    for (lut, lwe_out) in izip!(
        big_lut_as_polynomial_list.sublist_iter(small_lut_size),
        lwe_list_out.ciphertext_iter_mut(),
    ) {
        vertical_packing(lut, lwe_out, ggsw_list.as_view(), fft, stack.rb_mut());
    }
}

pub fn vertical_packing_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    lut_polynomial_count: PolynomialCount,
    ggsw_list_count: usize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let bits = core::mem::size_of::<Scalar>() * 8;

    // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // there is one polynomial, the number will be 0
    let log_lut_number: usize = bits - 1 - lut_polynomial_count.0.leading_zeros() as usize;

    let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list_count {
        // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
        // Blind rotation
        0
    } else {
        log_lut_number
    };

    StackReq::try_all_of([
        // cmux_tree_lut_res
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN)?,
        StackReq::try_any_of([
            blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft)?,
            cmux_tree_memory_optimized_scratch::<Scalar>(
                polynomial_size,
                glwe_size,
                log_number_of_luts_for_cmux_tree,
                fft,
            )?,
        ])?,
    ])
}

// GGSW ciphertexts are stored from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
pub fn vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
    lut: PolynomialList<&[Scalar]>,
    mut lwe_out: LweCiphertext<&mut [Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    let polynomial_size = ggsw_list.polynomial_size();
    let glwe_size = ggsw_list.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();

    debug_assert!(
        lwe_out.lwe_size().to_lwe_dimension().0 == polynomial_size.0 * glwe_dimension.0,
        "Output LWE ciphertext needs to have an LweDimension of {}, got {}",
        polynomial_size.0 * glwe_dimension.0,
        lwe_out.lwe_size().to_lwe_dimension().0,
    );

    // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // there is one polynomial, the number will be 0
    let log_lut_number: usize =
        Scalar::BITS - 1 - lut.polynomial_count().0.leading_zeros() as usize;

    let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list.count() {
        // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
        // Blind rotation
        0
    } else {
        log_lut_number
    };

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = ggsw_list.split_at(log_number_of_luts_for_cmux_tree);

    let (mut cmux_tree_lut_res_data, mut stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN, |_| {
            Scalar::ZERO
        });
    let mut cmux_tree_lut_res =
        GlweCiphertext::from_container(&mut *cmux_tree_lut_res_data, polynomial_size);

    cmux_tree_memory_optimized(
        cmux_tree_lut_res.as_mut_view(),
        lut,
        cmux_ggsw,
        fft,
        stack.rb_mut(),
    );
    blind_rotate(
        cmux_tree_lut_res.as_mut_view(),
        br_ggsw,
        fft,
        stack.rb_mut(),
    );

    // sample extract of the RLWE of the Vertical packing
    cmux_tree_lut_res.fill_lwe_with_sample_extraction(&mut lwe_out, MonomialDegree(0));
}

pub fn blind_rotate_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN)?,
        cmux_scratch::<Scalar>(glwe_size, polynomial_size, fft)?,
    ])
}

pub fn blind_rotate<Scalar: UnsignedTorus + CastInto<usize>>(
    mut lut: GlweCiphertext<&mut [Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    mut stack: DynStack<'_>,
) {
    let mut monomial_degree = MonomialDegree(1);

    for ggsw in ggsw_list.into_ggsw_iter().rev() {
        let ct_0 = lut.as_mut_view();
        let (mut ct1_data, stack) = stack.rb_mut().collect_aligned(
            CACHELINE_ALIGN,
            ct_0.as_view().into_container().iter().copied(),
        );
        let mut ct_1 = GlweCiphertext::from_container(&mut *ct1_data, ct_0.polynomial_size());
        ct_1.as_mut_polynomial_list()
            .update_with_wrapping_monic_monomial_div(monomial_degree);
        monomial_degree.0 <<= 1;
        cmux(ct_0, ct_1, ggsw, fft, stack);
    }
}

#[cfg(test)]
mod tests;
