use concrete_fftw::array::AlignedVec;
#[cfg(feature = "serde_serialize")]
use serde::{Deserialize, Serialize};

use crate::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use crate::backends::fftw::private::math::fft::{Complex64, FourierPolynomial};
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::commons::math::torus::UnsignedTorus;
use crate::prelude::ScalingFactor;
use concrete_commons::parameters::{GlweDimension, GlweSize, PolynomialSize};

/// A GLWE ciphertext in the Fourier Domain.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
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
        GlweCiphertext<InputCont>: AsRefTensor<Element = Scalar>,
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
    /// let mut fourier_glwe: FourierGlweCiphertext<_, u32> =
    ///     FourierGlweCiphertext::allocate(Complex64::new(0., 0.), PolynomialSize(128), GlweSize(7));
    ///
    /// let mut buffers = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    /// let mut buffers_out = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    ///
    /// let glwe = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    ///
    /// fourier_glwe.fill_with_forward_fourier(&glwe, &mut buffers);
    ///
    /// let mut glwe_out = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    ///
    /// fourier_glwe.fill_with_backward_fourier(&mut glwe_out, &mut buffers_out);
    /// ```
    pub fn fill_with_backward_fourier<InputCont, Scalar_>(
        &mut self,
        glwe: &mut GlweCiphertext<InputCont>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        GlweCiphertext<InputCont>: AsMutTensor<Element = Scalar_>,
        Scalar_: UnsignedTorus,
    {
        // We retrieve a buffer for the fft.
        let fft = &mut buffers.fft_buffers.fft;

        let mut poly_list = glwe.as_mut_polynomial_list();

        // we move every polynomial to the coefficient domain
        let iterator = poly_list
            .polynomial_iter_mut()
            .zip(self.polynomial_iter_mut());

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
        Self: AsRefTensor<Element = Complex64>,
        FourierGlweCiphertext<Container, Scalar>: AsRefTensor<Element = Complex64>,
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
        println!("output k: {}", output.glwe_size.0);
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
                        println!("i: {}", i);
                        let mut output_poly1 = iter_output.next().unwrap();
                        // 1. Put the T_i = A1i * A2i terms in the output
                        output_poly1.update_with_multiply_accumulate(&a1i, &a2i);
                        // Put A1i * B2 + B1 * A2i into the output
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
                            println!("i: {}, j: {}", i, j);
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
