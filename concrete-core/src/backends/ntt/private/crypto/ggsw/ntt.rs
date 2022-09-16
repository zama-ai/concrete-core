use crate::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::commons::utils::{zip, zip_args};

use crate::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::backends::ntt::private::math::polynomial::NttPolynomial;
use crate::backends::ntt::private::math::transform::Ntt;
use crate::commons::crypto::ggsw::{GgswLevelMatrix, StandardGgswCiphertext};
use crate::commons::crypto::glwe::{GlweCiphertext, GlweList};
use crate::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize};

/// A GGSW ciphertext in the NTT Domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttGgswCiphertext<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    decomp_base_log: DecompositionBaseLog,
}

impl<NttScalar: UnsignedInteger> NttGgswCiphertext<Vec<ModQ<NttScalar>>> {
    /// Allocates a new GGSW ciphertext in the NTT domain whose coefficients are all uninitialized.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.glwe_size(), GlweSize(7));
    /// assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// assert_eq!(ggsw.decomposition_base_log(), DecompositionBaseLog(4));
    /// assert_eq!(ggsw.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn allocate(
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self {
        let tensor =
            Tensor::from_container(vec![
                <ModQ<NttScalar>>::empty();
                decomp_level.0 * glwe_size.0 * glwe_size.0 * poly_size.0
            ]);

        NttGgswCiphertext {
            tensor,
            poly_size,
            glwe_size,
            decomp_base_log,
        }
    }
}

impl<Cont> NttGgswCiphertext<Cont> {
    /// Creates a GGSW ciphertext in the NTT domain from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::from_container(
    ///     vec![ModQ::new(0, MOD_32_128); 7 * 7 * 10 * 3],
    ///     GlweSize(7),
    ///     PolynomialSize(10),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.glwe_size(), GlweSize(7));
    /// assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// assert_eq!(ggsw.decomposition_base_log(), DecompositionBaseLog(4));
    /// assert_eq!(ggsw.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn from_container(
        cont: Cont,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => glwe_size.0, poly_size.0, glwe_size.0 * glwe_size.0);
        NttGgswCiphertext {
            tensor,
            poly_size,
            glwe_size,
            decomp_base_log,
        }
    }

    /// Returns the size of the glwe ciphertexts composing the ggsw ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of decomposition levels used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.glwe_size.0,
            self.poly_size.0,
            self.glwe_size.0 * self.glwe_size.0
        );
        DecompositionLevelCount(
            self.as_tensor().len() / (self.glwe_size.0 * self.glwe_size.0 * self.poly_size.0),
        )
    }

    /// Returns the size of the polynomials used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns a borrowed list composed of all the GLWE ciphertext composing current ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    ///     PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// let list = ggsw.as_glwe_list();
    /// assert_eq!(list.glwe_dimension(), GlweDimension(6));
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(3 * 7));
    /// ```
    pub fn as_glwe_list<E>(&self) -> GlweList<&[E]>
    where
        Self: AsRefTensor<Element = E>,
    {
        GlweList::from_container(
            self.as_tensor().as_slice(),
            self.glwe_size.to_glwe_dimension(),
            self.poly_size,
        )
    }

    /// Returns a mutably borrowed `GlweList` composed of all the GLWE ciphertext composing
    /// current ciphertext.
    ///
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{
    ///     CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    ///     PolynomialSize,
    /// };
    ///
    /// let mut ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// let mut list = ggsw.as_mut_glwe_list();
    /// list.as_mut_tensor()
    ///     .fill_with_element(ModQ::new(1u64, MOD_32_128));
    /// assert_eq!(list.glwe_dimension(), GlweDimension(6));
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(3 * 7));
    /// ggsw.as_tensor()
    ///     .iter()
    ///     .for_each(|a| assert_eq!(*a, ModQ::new(1u64, MOD_32_128)));
    /// ```
    pub fn as_mut_glwe_list<E>(&mut self) -> GlweList<&mut [E]>
    where
        Self: AsMutTensor<Element = E>,
    {
        let dimension = self.glwe_size.to_glwe_dimension();
        let size = self.poly_size;
        GlweList::from_container(self.as_mut_tensor().as_mut_slice(), dimension, size)
    }

    /// Returns the logarithm of the base used for the gadget decomposition.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.decomposition_base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns an iterator over borrowed level matrices.
    ///
    /// # Note
    ///
    /// This iterator iterates over the levels from the lower to the higher level in the usual
    /// order. To iterate in the reverse order, you can use `rev()` on the iterator.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// for level_matrix in ggsw.level_matrix_iter() {
    ///     assert_eq!(level_matrix.row_iter().count(), 7);
    ///     assert_eq!(level_matrix.polynomial_size(), PolynomialSize(9));
    ///     for glwe in level_matrix.row_iter() {
    ///         assert_eq!(glwe.glwe_size(), GlweSize(7));
    ///         assert_eq!(glwe.polynomial_size(), PolynomialSize(9));
    ///     }
    /// }
    /// assert_eq!(ggsw.level_matrix_iter().count(), 3);
    /// ```
    pub fn level_matrix_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = GgswLevelMatrix<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        let chunks_size = self.poly_size.0 * self.glwe_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let glwe_size = self.glwe_size;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    DecompositionLevel(index + 1),
                )
            })
    }

    /// Returns an iterator over mutably borrowed level matrices.
    ///
    /// # Note
    ///
    /// This iterator iterates over the levels from the lower to the higher level in the usual
    /// order. To iterate in the reverse order, you can use `rev()` on the iterator.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let mut ggsw: NttGgswCiphertext<Vec<ModQ<u64>>> = NttGgswCiphertext::allocate(
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// for mut level_matrix in ggsw.level_matrix_iter_mut() {
    ///     for mut glwe in level_matrix.row_iter_mut() {
    ///         glwe.as_mut_tensor()
    ///             .fill_with_element(ModQ::new(1u64, MOD_32_128));
    ///     }
    /// }
    /// assert!(ggsw
    ///     .as_tensor()
    ///     .iter()
    ///     .all(|a| *a == ModQ::new(1u64, MOD_32_128)));
    /// assert_eq!(ggsw.level_matrix_iter_mut().count(), 3);
    /// ```
    pub fn level_matrix_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = GgswLevelMatrix<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0 * self.glwe_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let glwe_size = self.glwe_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    DecompositionLevel(index + 1),
                )
            })
    }

    /// Fills a GGSW ciphertext with the NTT transform of a GGSW ciphertext in
    /// coefficient domain.
    pub fn fill_with_forward_ntt<InputCont, Scalar, NttScalar>(
        &mut self,
        coef_ggsw: &StandardGgswCiphertext<InputCont>,
        ntt: &mut Ntt<NttScalar>,
    ) where
        Cont: AsMutSlice<Element = ModQ<NttScalar>>,
        StandardGgswCiphertext<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + CastInto<NttScalar>,
        NttScalar: UnsignedInteger,
    {
        // // We move every polynomials to the NTT domain.
        let iterator = self
            .tensor
            .subtensor_iter_mut(self.poly_size.0)
            .map(|t| NttPolynomial::from_container(t.into_container()))
            .zip(
                coef_ggsw
                    .as_tensor()
                    .subtensor_iter(coef_ggsw.polynomial_size().0)
                    .map(|t| Polynomial::from_container(t.into_container())),
            );
        for (mut ntt_poly, coef_poly) in iterator {
            ntt.forward_w_mod_switch(&mut ntt_poly, &coef_poly);
        }
    }

    pub fn external_product<C1, C2, NttScalar, Scalar>(
        &self,
        output: &mut GlweCiphertext<C1>,
        glwe: &GlweCiphertext<C2>,
        rounded_buffer: &mut GlweCiphertext<Vec<Scalar>>,
        ntt: &mut Ntt<NttScalar>,
    ) where
        Self: AsRefTensor<Element = ModQ<NttScalar>>,
        NttScalar: UnsignedInteger,
        Scalar: UnsignedTorus + CastInto<NttScalar> + CastFrom<NttScalar>,
        GlweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        GlweCiphertext<C2>: AsRefTensor<Element = Scalar>,
    {
        // We check that the polynomial sizes match
        ck_dim_eq!(
            self.poly_size =>
            glwe.polynomial_size(),
            output.polynomial_size()
        );
        // We check that the glwe sizes match
        ck_dim_eq!(
            self.glwe_size() =>
            glwe.size(),
            output.size()
        );

        let rounded_input_glwe = rounded_buffer;
        // We round the input mask and body
        let decomposer =
            SignedDecomposer::new(self.decomp_base_log, self.decomposition_level_count());
        decomposer.fill_tensor_with_closest_representable(rounded_input_glwe, glwe);

        // ------------------------------------------------------ EXTERNAL PRODUCT IN NTT DOMAIN
        // In this section, we perform the external product in the NTT domain, and accumulate
        // the result in the output_fft_buffer variable.
        let mut decomposition = decomposer.decompose_tensor(rounded_input_glwe);

        let mut fft_buffer: NttPolynomial<Vec<ModQ<NttScalar>>> =
            NttPolynomial::allocate(ntt.get_zero_mod_q(), self.poly_size);
        let mut ntt_glwe_buffer: NttGlweCiphertext<Vec<ModQ<NttScalar>>> =
            NttGlweCiphertext::allocate(ntt.get_zero_mod_q(), self.poly_size, self.glwe_size);

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        for ggsw_decomp_matrix in self.level_matrix_iter().rev() {
            // We retrieve the decomposition of this level.
            let glwe_decomp_term = decomposition.next_term().unwrap();
            debug_assert_eq!(
                ggsw_decomp_matrix.decomposition_level(),
                glwe_decomp_term.level()
            );
            // For each levels we have to add the result of the vector-matrix product between the
            // decomposition of the glwe, and the ggsw level matrix to the output. To do so, we
            // iteratively add to the output, the product between every lines of the matrix, and
            // the corresponding (scalar) polynomial in the glwe decomposition:
            //
            //                ggsw_mat                        ggsw_mat
            //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
            //  | - - - | x | - - - - |         | - - - | x | - - - - | <
            //    ^         | - - - - |             ^       | - - - - |
            //
            //        t = 1                           t = 2                     ...
            let iterator = zip!(
                ggsw_decomp_matrix.row_iter(),
                glwe_decomp_term
                    .as_tensor()
                    .subtensor_iter(self.poly_size.0)
                    .map(Polynomial::from_tensor)
            );
            for (ggsw_row, glwe_poly) in iterator {
                // We perform the forward fft transform for the glwe polynomial
                ntt.forward_w_mod_switch(&mut fft_buffer, &glwe_poly);
                // Now we loop through the polynomials of the output, and add the
                // corresponding product of polynomials.
                let iterator = zip!(
                    ggsw_row
                        .as_tensor()
                        .subtensor_iter(self.poly_size.0)
                        .map(NttPolynomial::from_tensor),
                    ntt_glwe_buffer.polynomial_iter_mut()
                );
                for zip_args!(ggsw_poly, mut output_poly) in iterator {
                    output_poly.update_with_multiply_accumulate(&ggsw_poly, &fft_buffer);
                }
            }
        }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
        // In this section, we bring the result from the NTT domain, back to the standard
        // domain, and add it to the output.
        let mut _output_bind = output.as_mut_polynomial_list();
        for (mut out, ntt_poly) in zip!(
            _output_bind.polynomial_iter_mut(),
            ntt_glwe_buffer.polynomial_iter()
        ) {
            ntt.add_backward_w_mod_switch(&mut out, &ntt_poly);
        }
    }

    // This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
    pub fn cmux<C0, C1, NttScalar, Scalar>(
        &self,
        ct0: &mut GlweCiphertext<C0>,
        ct1: &mut GlweCiphertext<C1>,
        rounded_buffer: &mut GlweCiphertext<Vec<Scalar>>,
        ntt: &mut Ntt<NttScalar>,
    ) where
        Self: AsRefTensor<Element = ModQ<NttScalar>>,
        NttScalar: UnsignedInteger,
        Scalar: UnsignedTorus + CastInto<NttScalar> + CastFrom<NttScalar>,
        GlweCiphertext<C0>: AsMutTensor<Element = Scalar>,
        GlweCiphertext<C1>: AsMutTensor<Element = Scalar>,
    {
        ct1.as_mut_tensor()
            .update_with_wrapping_sub(ct0.as_tensor());
        self.external_product(ct0, ct1, rounded_buffer, ntt);
    }
}

impl<Element, Cont> AsRefTensor for NttGgswCiphertext<Cont>
where
    Cont: AsRefSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.tensor
    }
}

impl<Element, Cont> AsMutTensor for NttGgswCiphertext<Cont>
where
    Cont: AsMutSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.tensor
    }
}

impl<Cont> IntoTensor for NttGgswCiphertext<Cont>
where
    Cont: AsRefSlice,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.tensor
    }
}
