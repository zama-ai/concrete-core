use crate::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use crate::backends::fftw::private::math::fft::{Complex64, FourierPolynomial};
use crate::commons::crypto::glwe::{GlweCiphertext, GlweList};
use crate::commons::math::tensor::{
    AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, ck_dim_div, ck_dim_eq, IntoTensor, Tensor,
};
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::parameters::{GlweSize, PolynomialSize};
use crate::prelude::ScalingFactor;
use concrete_fftw::array::AlignedVec;
#[cfg(feature = "backend_fftw_serialization")]
use serde::{Deserialize, Serialize};

/// A GLWE ciphertext in the Fourier Domain.
#[cfg_attr(feature = "backend_fftw_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourierGlweCiphertext<Cont, Scalar> {
    tensor: Tensor<Cont>,
    pub poly_size: PolynomialSize,
    pub glwe_size: GlweSize,
    _scalar: std::marker::PhantomData<Scalar>,
}

impl<Scalar> FourierGlweCiphertext<AlignedVec<Complex64>, Scalar> {
    /// Allocates a new GLWE ciphertext in the Fourier domain whose coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// let glwe: FourierGlweCiphertext<_, u32> =
    ///     FourierGlweCiphertext::allocate(Complex64::new(0., 0.), PolynomialSize(10), GlweSize(7));
    /// assert_eq!(glwe.glwe_size(), GlweSize(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn allocate(value: Complex64, poly_size: PolynomialSize, glwe_size: GlweSize) -> Self
    where
        Scalar: Copy,
    {
        let mut tensor = Tensor::from_container(AlignedVec::new(glwe_size.0 * poly_size.0));
        tensor.as_mut_tensor().fill_with_element(value);
        FourierGlweCiphertext {
            tensor,
            poly_size,
            glwe_size,
            _scalar: Default::default(),
        }
    }
}

impl<Cont, Scalar: UnsignedTorus> FourierGlweCiphertext<Cont, Scalar> {
    /// Creates a GLWE ciphertext in the Fourier domain from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    ///
    /// let glwe: FourierGlweCiphertext<_, u32> = FourierGlweCiphertext::from_container(
    ///     vec![Complex64::new(0., 0.); 7 * 10],
    ///     GlweSize(7),
    ///     PolynomialSize(10),
    /// );
    /// assert_eq!(glwe.glwe_size(), GlweSize(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn from_container(cont: Cont, glwe_size: GlweSize, poly_size: PolynomialSize) -> Self
        where
            Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => glwe_size.0, poly_size.0);
        FourierGlweCiphertext {
            tensor,
            poly_size,
            glwe_size,
            _scalar: Default::default(),
        }
    }

    /// Returns the size of the GLWE ciphertext
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    ///
    /// let glwe: FourierGlweCiphertext<_, u32> =
    ///     FourierGlweCiphertext::allocate(Complex64::new(0., 0.), PolynomialSize(10), GlweSize(7));
    /// assert_eq!(glwe.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the size of the polynomials used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    ///
    /// let glwe: FourierGlweCiphertext<_, u32> =
    ///     FourierGlweCiphertext::allocate(Complex64::new(0., 0.), PolynomialSize(10), GlweSize(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }
    
    /// Returns an iterator over references to the polynomials contained in the GLWE.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::PolynomialSize;
    /// use concrete_core::commons::math::polynomial::PolynomialList;
    /// let mut list =
    ///     PolynomialList::from_container(vec![1u8, 2, 3, 4, 5, 6, 7, 8], PolynomialSize(2));
    /// for polynomial in list.polynomial_iter() {
    ///     assert_eq!(polynomial.polynomial_size(), PolynomialSize(2));
    /// }
    /// assert_eq!(list.polynomial_iter().count(), 4);
    /// ```
    pub fn polynomial_iter(
        &self,
    ) -> impl Iterator<Item = FourierPolynomial<&[<Self as AsRefTensor>::Element]>>
        where
            Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.poly_size.0)
            .map(FourierPolynomial::from_tensor)
    }

    /// Returns an iterator over mutable references to the polynomials contained in the list.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{MonomialDegree, PolynomialSize};
    /// use concrete_core::commons::math::polynomial::PolynomialList;
    /// let mut list =
    ///     PolynomialList::from_container(vec![1u8, 2, 3, 4, 5, 6, 7, 8], PolynomialSize(2));
    /// for mut polynomial in list.polynomial_iter_mut() {
    ///     polynomial
    ///         .get_mut_monomial(MonomialDegree(0))
    ///         .set_coefficient(10u8);
    ///     assert_eq!(polynomial.polynomial_size(), PolynomialSize(2));
    /// }
    /// for polynomial in list.polynomial_iter() {
    ///     assert_eq!(
    ///         *polynomial.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///         10u8
    ///     );
    /// }
    /// assert_eq!(list.polynomial_iter_mut().count(), 4);
    /// ```
    pub fn polynomial_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = FourierPolynomial<&mut [<Self as AsMutTensor>::Element]>>
        where
            Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(FourierPolynomial::from_tensor)
    }

}

impl<Scalar: UnsignedTorus> FourierGlweCiphertext<AlignedVec<Complex64>, Scalar> {
    /// Fills a Fourier GLWE ciphertext with the Fourier transform of a GLWE ciphertext in
    /// coefficient domain.
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::bootstrap::FourierBuffers;
    /// use concrete_core::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::commons::crypto::glwe::GlweCiphertext;
    /// let mut fourier_glwe: FourierGlweCiphertext<_, u32> =
    ///     FourierGlweCiphertext::allocate(Complex64::new(0., 0.), PolynomialSize(128), GlweSize(7));
    ///
    /// let mut buffers = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    ///
    /// let glwe = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    ///
    /// fourier_glwe.fill_with_forward_fourier(&glwe, &mut buffers)
    /// ```
    pub fn fill_with_forward_fourier<InputCont>(
        &mut self,
        glwe: &GlweCiphertext<InputCont>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        GlweCiphertext<InputCont>: AsRefTensor<Element=Scalar>,
        Scalar: UnsignedTorus,
    {
        // We retrieve a buffer for the fft.
        let fft_buffer = &mut buffers.fft_buffers.first_buffer;
        let fft = &mut buffers.fft_buffers.fft;

        // We move every polynomial to the fourier domain.
        let poly_list = glwe.as_polynomial_list();
        let iterator = self.polynomial_iter_mut().zip(poly_list.polynomial_iter());
        for (mut fourier_poly, coef_poly) in iterator {
            fft.forward_as_torus(fft_buffer, &coef_poly);
            fourier_poly
                .as_mut_tensor()
                .fill_with_one((fft_buffer).as_tensor(), |a| *a);
        }
    }

    /// Fills a GLWE ciphertext with the inverse fourier transform of a Fourier GLWE ciphertext
    /// ```
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::bootstrap::FourierBuffers;
    /// use concrete_core::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::commons::crypto::glwe::GlweCiphertext;
    ///
    /// let fourier_glwe: FourierGlweCiphertext<_, u32> =
    ///     FourierGlweCiphertext::allocate(Complex64::new(0., 0.), PolynomialSize(128), GlweSize(7));
    ///
    /// let mut buffers = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    /// let mut buffers_out = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    ///
    /// let mut glwe = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    ///
    /// fourier_glwe.fill_glwe_with_backward_fourier(&mut glwe, &mut buffers);
    ///
    /// let mut glwe_out = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    ///
    /// fourier_glwe.fill_glwe_with_backward_fourier(&mut glwe_out, &mut buffers_out);
    /// ```
    pub fn fill_glwe_with_backward_fourier<InputCont>(
        &self,
        glwe: &mut GlweCiphertext<InputCont>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        Cont: AsMutSlice<Element = Complex64>,
        GlweCiphertext<InputCont>: AsMutTensor<Element = Scalar>,
    {
        // We get the fft to use from the passed buffers
        let fft = &mut buffers.fft_buffers.fft;

        // Output buffer is large enough to hold self which is a FourierGlweCiphertext
        let input_fourier_polynomials_buffer = &mut buffers.fft_buffers.output_buffer;

        input_fourier_polynomials_buffer
            .as_mut_tensor()
            .fill_with_copy(self.as_tensor());

        // Create an iterator that takes chunk of the input buffer and map these to polynomials
        let input_fourier_polynomials_list = input_fourier_polynomials_buffer
            .subtensor_iter_mut(self.poly_size.0)
            .map(FourierPolynomial::from_tensor);

        // Prepare the output polynomials list
        let mut output_std_glwe_polynomials = glwe.as_mut_polynomial_list();

        // Prepare the iterator for the backward calls
        let iterator = output_std_glwe_polynomials
            .polynomial_iter_mut()
            .zip(input_fourier_polynomials_list);

        for (mut coef_poly, mut fourier_poly) in iterator {
            fft.backward_as_torus(&mut coef_poly, &mut fourier_poly);
        }
    }

    /// Returns the tensor product of two Fourier GLWE ciphertexts
    pub fn tensor_product_same_key<Container>(
        &self,
        glwe: &FourierGlweCiphertext<Container, Scalar>,
        scale: ScalingFactor,
    ) -> FourierGlweCiphertext<AlignedVec<Complex64>, Scalar>
        where
            Self: AsRefTensor<Element=Complex64>,
            FourierGlweCiphertext<Container, Scalar>: AsRefTensor<Element=Complex64>,
    {
        // We check that the polynomial sizes match
        ck_dim_eq!(
            self.poly_size =>
            glwe.polynomial_size(),
            self.polynomial_size()
        );
        // We check that the glwe sizes match
        ck_dim_eq!(
            self.glwe_size() =>
            glwe.glwe_size(),
            self.glwe_size()
        );

        let k = self.glwe_size().to_glwe_dimension().0;
        let new_k = GlweDimension(k + k * (k - 1) / 2 + k);

        // create an output FourierGLWECiphertext of the correct size
        let mut output = FourierGlweCiphertext::allocate(
            Complex64::new(0., 0.),
            self.poly_size,
            new_k.to_glwe_size(),
        );
        let iter_glwe_1 = self.polynomial_iter();
        {
            let mut iter_output = output.polynomial_iter_mut();
            // Here the output contains all the multiplied terms
            // in the order defined by the loops:
            // (T_0, A_0', R_ij, ...., T_1, A_1', .... )
            // The a1i, a2i, a1j, a2j, b1i, b2j variables below represent the mask and body
            // polynomials, even though they are not in capital letters to respect our variable 
            // names format.
            for (i, a1i) in iter_glwe_1.enumerate() {
                // The last polynomial in self is the body, we need to handle it specifically
                if i == self.glwe_size.0 - 1 {
                    // Get the body polynomial
                    let mut output_poly = iter_output.next().unwrap();
                    let b1 = self.polynomial_iter().last().unwrap();
                    let b2 = glwe.polynomial_iter().last().unwrap();
                    // Modify the body
                    output_poly.update_with_multiply_accumulate(&b1, &b2);
                    break;
                }
                let iter_glwe_2 = glwe.polynomial_iter();
                // consumes the iterator object with enumerate()
                for (j, a2i) in iter_glwe_2.enumerate() {
                    if i == j {
                        let mut output_poly1 = iter_output.next().unwrap();
                        // 1. Put the T_i = A1i * A2i terms in the output
                        output_poly1.update_with_multiply_accumulate(&a1i, &a2i);
                        // 2. Put A1i * B2 + B1 * A2i into the output
                        // create new iterators for glwe_1 and glwe_2
                        // A_i'
                        let mut output_poly2 = iter_output.next().unwrap();
                        let b1 = self.polynomial_iter().last().unwrap();
                        let b2 = glwe.polynomial_iter().last().unwrap();
                        output_poly2.update_with_two_multiply_accumulate(
                            &a1i,
                            &b2,
                            &b1,
                            &a2i,
                        );
                    } else {
                        // When i and j are different, only compute the terms where j < i for R_ij
                        if j < i {
                            let mut output_poly = iter_output.next().unwrap();
                            // Put A1i * A2j + A1j * A2i
                            let a1j = self.polynomial_iter().nth(j).unwrap();
                            let a2i = glwe.polynomial_iter().nth(i).unwrap();
                            output_poly.update_with_two_multiply_accumulate(
                                &a1i,
                                &a2i,
                                &a1j,
                                &a2i,
                            )
                        }
                    }
                }
            }
        }
        let iter_output = output.polynomial_iter_mut();

        for (_i, mut polynomial_out) in iter_output.enumerate() {
            for coef in polynomial_out.coefficient_iter_mut() {
                *coef /= scale.0 as f64;
            }
        }
        output
    }

    // Computes the relinearization of a Fourier GLWE ciphertext using a relinearization key 
    // (originally in the standard domain)
    pub fn relinearize<Container>(
        &self,
        rlk: &StandardGlweRelinearizationKey<Container>,
        buffers: &mut FourierBuffers<Scalar>,
    ) -> FourierGlweCiphertext<AlignedVec<Complex64>, Scalar>
        where
            Self: AsRefTensor<Element=Complex64>,
            FourierGlweCiphertext<Container, Scalar>: AsRefTensor<Element=Complex64>,
    {
        // Here self has to be the result of a tensor product operation with a structure
        // (A_i', T_i, R_ij, B'). Relinearization consists in computing:
        //  (A_i, .. A_k, B) = (A_i', .. A_k', B') + sum(RLK_ii * dec(T_i), i = 0..k) + 
        //   sum(RLK_ij * dec(R_ij), i=0..k, j=0..i)

        // Self's GLWE size is (k^2 + k) / 2, where k is the GLWE dimension of the original GLWE 
        // ciphertexts. (k^2 + k) / 2 is the Glev count of the relinearization key. 
        ck_dim_eq!(
            self.glwe_size().to_glwe_dimension().0 => rlk.glev_count()
        );

        // The output of the relinearization will have the GLWE size of the relinearization key
        let mut output = FourierGlweCiphertext::allocate(
            Complex64::new(0., 0.),
            self.poly_size,
            rlk.glwe_size(),
        );

        // Step 1. Copy (A_1', .. A_k', B')
        let mut output_iter = output.polynomial_iter_mut();

        for (i, mut poly) in output_iter.enumerate() {
            if i < rlk.glwe_size().0 - 1 {
                let a_i = self.get_tensor_product_t_index(i) + 1;
                self.polynomial_iter().nth(a_i).unwrap().copy_polynomial_content(&poly);
            } else {
                // Copy B' into the last polynomial of the output
                self.polynomial_iter().last().unwrap().copy_polynomial_content(&poly);
            }
        }

        // Step 2. Sum the product of the RLK terms with the decomposition of the relevant 
        // components (T_i, R_ij) of the input ciphertext in the standard domain. 
        // The conversion to the standard domain happens here rather than at the
        // end of the tensor product, in case we want to chain tensor products later on. 
        // In this way we can keep all ciphertexts in the Fourier domain until the 
        // relinearization happens.
        // We convert back to the Fourier domain for the product with the RLK itself.

        for (i, mut output_poly) in output_iter.enumerate() {
            let t_i = self.get_tensor_product_t_index(i);
            let mut t_i_fourier_poly = self.polynomial_iter().nth(t_i).unwrap();
            let mut t_i_poly = Polynomial::allocate(Scalar::ZERO, rlk.polynomial_size());
            fft.backward_as_torus(&mut t_i_poly, &mut t_i_fourier_poly);
            rlk.compute_relinearization_product(&mut output_poly, &t_i_poly, i, i, buffers);

            for j in 0..i {
                let r_ij = self.get_tensor_product_t_index(i) + j + 2;
                let mut r_ij_fourier_poly = self.polynomial_iter().nth(r_ij).unwrap();
                let mut r_ij_poly = Polynomial::allocate(Scalar::ZERO, rlk.polynomial_size());
                fft.backward_as_torus(&mut r_ij_poly, &mut r_ij_fourier_poly);
                rlk.compute_relinearization_product(&mut output_poly, &r_ij_poly, i, j,
                                                    buffers);
            }
        }
        output
    }

    /// This function computes the leveled multiplication between two GLWE ciphertexts in the 
    /// Fourier domain
    pub fn compute_leveled_multiplication<Container>(
        &self,
        glwe: &FourierGlweCiphertext<Container, Scalar>,
        scale: ScalingFactor,
        rlk: &StandardGlweRelinearizationKey<Container>,
        buffers: &mut FourierBuffers<Scalar>,
    ) -> FourierGlweCiphertext<AlignedVec<Complex64>, Scalar>
        where
            Self: AsRefTensor<Element=Complex64>,
            FourierGlweCiphertext<Container, Scalar>: AsRefTensor<Element=Complex64>,
    {
        // We check that the polynomial sizes match
        ck_dim_eq!(
            self.poly_size =>
            glwe.polynomial_size(),
            self.polynomial_size()
        );
        // We check that the glwe sizes match
        ck_dim_eq!(
            self.glwe_size() =>
            glwe.glwe_size(),
            self.glwe_size()
        );
        let tensor_prod_fourier_glwe = self.tensor_product_same_key(glwe, scale);

        tensor_prod_fourier_glwe.relinearize(rlk, buffers)
    }
}


impl<Element, Cont, Scalar> AsRefTensor for FourierGlweCiphertext<Cont, Scalar>
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

impl<Element, Cont, Scalar> AsMutTensor for FourierGlweCiphertext<Cont, Scalar>
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

impl<Cont, Scalar> IntoTensor for FourierGlweCiphertext<Cont, Scalar>
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

