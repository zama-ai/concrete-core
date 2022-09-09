use crate::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::commons::utils::{zip, zip_args};
use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize};

use concrete_fftw::array::AlignedVec;

use crate::backends::fftw::private::crypto::bootstrap::fourier::FftBuffers;
use crate::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use crate::backends::fftw::private::math::fft::{Complex64, FourierPolynomial};
use crate::commons::crypto::ggsw::{GgswLevelMatrix, StandardGgswCiphertext};
use crate::commons::crypto::glwe::{GlweCiphertext, GlweList};
use crate::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::torus::UnsignedTorus;
#[cfg(feature = "backend_fftw_serialization")]
use serde::{Deserialize, Serialize};

/// A GGSW ciphertext in the Fourier Domain.
#[cfg_attr(feature = "backend_fftw_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourierGgswCiphertext<Cont, Scalar> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    decomp_base_log: DecompositionBaseLog,
    _scalar: std::marker::PhantomData<Scalar>,
}

impl<Scalar> FourierGgswCiphertext<AlignedVec<Complex64>, Scalar> {
    /// Allocates a new GGSW ciphertext in the Fourier domain whose coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
        value: Complex64,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self
    where
        Scalar: Copy,
    {
        let mut tensor = Tensor::from_container(AlignedVec::new(
            decomp_level.0 * glwe_size.0 * glwe_size.0 * poly_size.0,
        ));
        tensor.as_mut_tensor().fill_with_element(value);
        FourierGgswCiphertext {
            tensor,
            poly_size,
            glwe_size,
            decomp_base_log,
            _scalar: Default::default(),
        }
    }
}

impl<Cont, Scalar> FourierGgswCiphertext<Cont, Scalar> {
    /// Creates a GGSW ciphertext in the Fourier domain from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::from_container(
    ///     vec![Complex64::new(0., 0.); 7 * 7 * 10 * 3],
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
        FourierGgswCiphertext {
            tensor,
            poly_size,
            glwe_size,
            decomp_base_log,
            _scalar: Default::default(),
        }
    }

    /// Returns the size of the glwe ciphertexts composing the ggsw ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    ///     PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{
    ///     CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    ///     PolynomialSize,
    /// };
    ///
    /// let mut ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// let mut list = ggsw.as_mut_glwe_list();
    /// list.as_mut_tensor()
    ///     .fill_with_element(Complex64::new(0., 0.));
    /// assert_eq!(list.glwe_dimension(), GlweDimension(6));
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(3 * 7));
    /// ggsw.as_tensor()
    ///     .iter()
    ///     .for_each(|a| assert_eq!(*a, Complex64::new(0., 0.)));
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
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
    /// use concrete_core::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let mut ggsw: FourierGgswCiphertext<_, u32> = FourierGgswCiphertext::allocate(
    ///     Complex64::new(0., 0.),
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// for mut level_matrix in ggsw.level_matrix_iter_mut() {
    ///     for mut glwe in level_matrix.row_iter_mut() {
    ///         glwe.as_mut_tensor()
    ///             .fill_with_element(Complex64::new(0., 0.));
    ///     }
    /// }
    /// assert!(ggsw
    ///     .as_tensor()
    ///     .iter()
    ///     .all(|a| *a == Complex64::new(0., 0.)));
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

    /// Fills a GGSW ciphertext with the fourier transform of a GGSW ciphertext in
    /// coefficient domain.
    pub fn fill_with_forward_fourier<InputCont>(
        &mut self,
        coef_ggsw: &StandardGgswCiphertext<InputCont>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        Cont: AsMutSlice<Element = Complex64>,
        StandardGgswCiphertext<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        // We retrieve a buffer for the fft.
        let fft_buffer = &mut buffers.fft_buffers.first_buffer;
        let fft = &mut buffers.fft_buffers.fft;

        // We move every polynomials to the fourier domain.
        let iterator = self
            .tensor
            .subtensor_iter_mut(self.poly_size.0)
            .map(|t| FourierPolynomial::from_container(t.into_container()))
            .zip(
                coef_ggsw
                    .as_tensor()
                    .subtensor_iter(coef_ggsw.polynomial_size().0)
                    .map(|t| Polynomial::from_container(t.into_container())),
            );
        for (mut fourier_poly, coef_poly) in iterator {
            fft.forward_as_torus(fft_buffer, &coef_poly);
            fourier_poly
                .as_mut_tensor()
                .fill_with_one((fft_buffer).as_tensor(), |a| *a);
        }
    }

    pub fn external_product<C1, C2>(
        &self,
        output: &mut GlweCiphertext<C1>,
        glwe: &GlweCiphertext<C2>,
        fft_buffers: &mut FftBuffers,
        rounded_buffer: &mut GlweCiphertext<Vec<Scalar>>,
    ) where
        Self: AsRefTensor<Element = Complex64>,
        GlweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        GlweCiphertext<C2>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
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

        // "alias" buffers to save some typing
        let fft = &mut fft_buffers.fft;
        let first_fft_buffer = &mut fft_buffers.first_buffer;
        let second_fft_buffer = &mut fft_buffers.second_buffer;
        let output_fft_buffer = &mut fft_buffers.output_buffer;
        output_fft_buffer.fill_with_element(Complex64::new(0., 0.));

        let rounded_input_glwe = rounded_buffer;

        // We round the input mask and body
        let decomposer =
            SignedDecomposer::new(self.decomp_base_log, self.decomposition_level_count());
        decomposer.fill_tensor_with_closest_representable(rounded_input_glwe, glwe);

        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let mut decomposition = decomposer.decompose_tensor(rounded_input_glwe);
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
            // When possible we iterate two times in a row, to benefit from the fact that fft can
            // transform two polynomials at once.
            let mut iterator = zip!(
                ggsw_decomp_matrix.row_iter(),
                glwe_decomp_term
                    .as_tensor()
                    .subtensor_iter(self.poly_size.0)
                    .map(Polynomial::from_tensor)
            );

            //---------------------------------------------------------------- VECTOR-MATRIX PRODUCT
            loop {
                match (iterator.next(), iterator.next()) {
                    // Two iterates are available, we use the fast fft.
                    (Some(first), Some(second)) => {
                        // We unpack the iterator values
                        let zip_args!(first_ggsw_row, first_glwe_poly) = first;
                        let zip_args!(second_ggsw_row, second_glwe_poly) = second;
                        // We perform the forward fft transform for the glwe polynomials
                        fft.forward_two_as_integer(
                            first_fft_buffer,
                            second_fft_buffer,
                            &first_glwe_poly,
                            &second_glwe_poly,
                        );
                        // Now we loop through the polynomials of the output, and add the
                        // corresponding product of polynomials.
                        let iterator = zip!(
                            first_ggsw_row
                                .as_tensor()
                                .subtensor_iter(self.poly_size.0)
                                .map(FourierPolynomial::from_tensor),
                            second_ggsw_row
                                .as_tensor()
                                .subtensor_iter(self.poly_size.0)
                                .map(FourierPolynomial::from_tensor),
                            output_fft_buffer
                                .as_mut_tensor()
                                .subtensor_iter_mut(self.poly_size.0)
                                .map(FourierPolynomial::from_tensor)
                        );
                        for zip_args!(first_ggsw_poly, second_ggsw_poly, mut output_poly) in
                            iterator
                        {
                            output_poly.update_with_two_multiply_accumulate(
                                &first_ggsw_poly,
                                first_fft_buffer,
                                &second_ggsw_poly,
                                second_fft_buffer,
                            );
                        }
                    }
                    // We reach the  end of the loop and one element remains.
                    (Some(first), None) => {
                        // We unpack the iterator values
                        let (first_ggsw_row, first_glwe_poly) = first;
                        // We perform the forward fft transform for the glwe polynomial
                        fft.forward_as_integer(first_fft_buffer, &first_glwe_poly);
                        // Now we loop through the polynomials of the output, and add the
                        // corresponding product of polynomials.
                        let iterator = zip!(
                            first_ggsw_row
                                .as_tensor()
                                .subtensor_iter(self.poly_size.0)
                                .map(FourierPolynomial::from_tensor),
                            output_fft_buffer
                                .subtensor_iter_mut(self.poly_size.0)
                                .map(FourierPolynomial::from_tensor)
                        );
                        for zip_args!(first_ggsw_poly, mut output_poly) in iterator {
                            output_poly.update_with_multiply_accumulate(
                                &first_ggsw_poly,
                                first_fft_buffer,
                            );
                        }
                    }
                    // The loop is over, we can exit.
                    _ => break,
                }
            }
        }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
        // In this section, we bring the result from the fourier domain, back to the standard
        // domain, and add it to the output.
        //
        // We iterate over the polynomials in the output. Again, when possible, we process two
        // iterations simultaneously to benefit from the fft acceleration.
        let mut _output_bind = output.as_mut_polynomial_list();
        let mut iterator = zip!(
            _output_bind.polynomial_iter_mut(),
            output_fft_buffer
                .subtensor_iter_mut(self.poly_size.0)
                .map(FourierPolynomial::from_tensor)
        );
        loop {
            match (iterator.next(), iterator.next()) {
                (Some(first), Some(second)) => {
                    // We unpack the iterates
                    let zip_args!(mut first_output, mut first_fourier) = first;
                    let zip_args!(mut second_output, mut second_fourier) = second;
                    // We perform the backward transform
                    fft.add_backward_two_as_torus(
                        &mut first_output,
                        &mut second_output,
                        &mut first_fourier,
                        &mut second_fourier,
                    );
                }
                (Some(first), None) => {
                    // We unpack the iterates
                    let (mut first_output, mut first_fourier) = first;
                    // We perform the backward transform
                    fft.add_backward_as_torus(&mut first_output, &mut first_fourier);
                }
                _ => break,
            }
        }
    }

    // This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
    pub fn cmux<C0, C1>(
        &self,
        ct0: &mut GlweCiphertext<C0>,
        ct1: &mut GlweCiphertext<C1>,
        fft_buffers: &mut FftBuffers,
        rounded_buffer: &mut GlweCiphertext<Vec<Scalar>>,
    ) where
        Self: AsRefTensor<Element = Complex64>,
        GlweCiphertext<C0>: AsMutTensor<Element = Scalar>,
        GlweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        ct1.as_mut_tensor()
            .update_with_wrapping_sub(ct0.as_tensor());
        self.external_product(ct0, ct1, fft_buffers, rounded_buffer);
    }

    // This cmux does not mutate its inputs. It outputs the result in ct_output, using ct_buffer for
    // some intermediate value computations.
    pub fn discard_cmux<C1, C2, C3, C4>(
        &self,
        ct_0: &GlweCiphertext<C1>,
        ct_1: &GlweCiphertext<C2>,
        ct_output: &mut GlweCiphertext<C3>,
        ct_buffer: &mut GlweCiphertext<C4>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        Self: AsRefTensor<Element = Complex64>,
        Scalar: UnsignedTorus,
        C1: AsRefSlice<Element = Scalar>,
        C2: AsRefSlice<Element = Scalar>,
        C3: AsMutSlice<Element = Scalar>,
        C4: AsMutSlice<Element = Scalar>,
    {
        ct_buffer
            .as_mut_tensor()
            .fill_with_wrapping_sub(ct_1.as_tensor(), ct_0.as_tensor());
        ct_output.as_mut_tensor().fill_with_element(Scalar::ZERO);
        self.external_product(
            ct_output,
            ct_buffer,
            &mut buffers.fft_buffers,
            &mut buffers.rounded_buffer,
        );
        ct_output
            .as_mut_tensor()
            .update_with_wrapping_add(ct_0.as_tensor())
    }
}

impl<Element, Cont, Scalar> AsRefTensor for FourierGgswCiphertext<Cont, Scalar>
where
    Cont: AsRefSlice<Element = Element>,
    Scalar: UnsignedTorus,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.tensor
    }
}

impl<Element, Cont, Scalar> AsMutTensor for FourierGgswCiphertext<Cont, Scalar>
where
    Cont: AsMutSlice<Element = Element>,
    Scalar: UnsignedTorus,
{
    type Element = Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.tensor
    }
}

impl<Cont, Scalar> IntoTensor for FourierGgswCiphertext<Cont, Scalar>
where
    Cont: AsRefSlice,
    Scalar: UnsignedTorus,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.tensor
    }
}
