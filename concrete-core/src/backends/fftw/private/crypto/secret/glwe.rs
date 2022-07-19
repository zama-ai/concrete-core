use crate::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use crate::backends::fftw::private::math::fft::{AlignedVec, Complex64, FourierPolynomial};
use crate::commons::crypto::secret::GlweSecretKey;
use crate::commons::math::tensor::{ck_dim_div, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor, IntoTensor};
use crate::commons::math::torus::UnsignedTorus;
use crate::prelude::{GlweDimension, KeyKind, PolynomialSize, TensorProductKeyKind};
use std::marker::PhantomData;
#[cfg(feature = "serde_serialize")]
use serde::{Deserialize, Serialize};
use crate::commons::math::random::ByteRandomGenerator;

/// A GLWE secret key in the Fourier Domain.
pub struct FourierGlweSecretKey<Kind, Cont, Scalar>
where
    Kind: KeyKind,
{
    tensor: Tensor<Cont>,
    pub poly_size: PolynomialSize,
    _kind: PhantomData<Kind>,
    _scalar: PhantomData<Scalar>,
}

impl<Kind, Scalar> FourierGlweSecretKey<Kind, AlignedVec<Complex64>, Scalar>
    where
        Kind: KeyKind,
{
    /// Allocates a new GLWE secret key in the Fourier domain whose coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::BinaryKeyKind;
    /// let glwe: FourierGlweSecretKey<BinaryKeyKind, _, u32> = FourierGlweSecretKey::allocate(
    ///     Complex64::new(0., 0.),
    ///     PolynomialSize(10),
    ///     GlweDimension(7),
    /// );
    /// assert_eq!(glwe.glwe_dimension(), GlweDimension(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn allocate(
        value: Complex64,
        poly_size: PolynomialSize,
        glwe_dimension: GlweDimension,
    ) -> Self
    where
        Scalar: Copy,
    {
        let mut tensor = Tensor::from_container(AlignedVec::new(glwe_dimension.0 * poly_size.0));
        tensor.as_mut_tensor().fill_with_element(value);
        FourierGlweSecretKey {
            tensor,
            poly_size,
            _kind: Default::default(),
            _scalar: Default::default(),
        }
    }
}

impl<Kind, Cont, Scalar: UnsignedTorus> FourierGlweSecretKey<Kind, Cont, Scalar>
    where
    Kind: KeyKind,
{
    /// Creates a GLWE secret key in the Fourier domain from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::BinaryKeyKind;
    ///
    /// let glwe_key: FourierGlweSecretKey<BinaryKeyKind, _, u32> =
    ///     FourierGlweSecretKey::from_container(
    ///         vec![Complex64::new(0., 0.); 7 * 10],
    ///         GlweDimension(7),
    ///         PolynomialSize(10),
    ///     );
    /// assert_eq!(glwe.glwe_dimension(), GlweDimension(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn from_container(
        cont: Cont,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => glwe_dimension.0, poly_size.0);
        FourierGlweSecretKey {
            tensor,
            poly_size,
            _kind: Default::default(),
            _scalar: Default::default(),
        }
    }

    /// Returns the dimension of the GLWE secret key
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::BinaryKeyKind;
    ///
    /// let glwe: FourierGlweSecretKey<BinaryKeyKind, _, u32> = FourierGlweSecretKey::allocate(
    ///     Complex64::new(0., 0.),
    ///     PolynomialSize(10),
    ///     GlweDimension(7),
    /// );
    /// assert_eq!(glwe.glwe_dimension(), GlweDimension(7));
    /// ```
    pub fn glwe_dimension(&self) -> GlweDimension
        where
        Cont: AsRefSlice,
    {
        GlweDimension(self.as_tensor().len() / self.poly_size.0)
    }

    /// Returns the size of the polynomials used in the secret key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::prelude::BinaryKeyKind;
    ///
    /// let glwe: FourierGlweSecretKey<BinaryKeyKind, _, u32> = FourierGlweSecretKey::allocate(
    ///     Complex64::new(0., 0.),
    ///     PolynomialSize(10),
    ///     GlweDimension(7),
    /// );
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Fills a Fourier GLWE secret key with the Fourier transform of a GLWE secret key in
    /// coefficient domain.
    ///
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::bootstrap::FourierBuffers;
    /// use concrete_core::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use concrete_core::commons::crypto::secret::GlweSecretKey;
    /// use concrete_core::commons::math::random::Seed;
    /// use concrete_core::prelude::BinaryKeyKind;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// let mut fourier_glwe_key: FourierGlweSecretKey<BinaryKeyKind, _, u32> =
    ///     FourierGlweSecretKey::allocate(
    ///         Complex64::new(0., 0.),
    ///         PolynomialSize(128),
    ///         GlweDimension(7),
    ///     );
    ///
    /// let mut buffers = FourierBuffers::new(fourier_glwe_key.poly_size, fourier_glwe_key.glwe_size);
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(7),
    ///     PolynomialSize(128),
    ///     &mut secret_generator,
    /// );
    ///
    /// fourier_glwe_key.fill_with_forward_fourier(&secret_key, &mut buffers)
    /// ```
    pub fn fill_with_forward_fourier<InputCont>(
        &mut self,
        glwe_key: &GlweSecretKey<Kind, InputCont>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        Cont: AsMutSlice<Element = Complex64>,
        GlweSecretKey<Kind, InputCont>: AsRefTensor<Element = Scalar>,
    {
        // We retrieve a buffer for the fft.
        let fft_buffer = &mut buffers.fft_buffers.first_buffer;
        let fft = &mut buffers.fft_buffers.fft;

        // We move every polynomial to the fourier domain.
        let poly_list = glwe_key.as_polynomial_list();
        let iterator = self.polynomial_iter_mut().zip(poly_list.polynomial_iter());
        for (mut fourier_poly, coef_poly) in iterator {
            fft.forward_as_torus(fft_buffer, &coef_poly);
            fourier_poly
                .as_mut_tensor()
                .fill_with_one((fft_buffer).as_tensor(), |a| *a);
        }
    }

    /// Fills a GLWE secret key with the inverse fourier transform of a Fourier GLWE secret key
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::backends::fftw::private::crypto::bootstrap::FourierBuffers;
    /// use concrete_core::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
    /// use concrete_core::backends::fftw::private::math::fft::Complex64;
    /// use concrete_core::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use concrete_core::commons::crypto::secret::GlweSecretKey;
    /// use concrete_core::commons::math::random::Seed;
    /// use concrete_core::prelude::BinaryKeyKind;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    ///
    /// let mut fourier_glwe: FourierGlweSecretKey<BinaryKeyKind, _, u32> =
    ///     FourierGlweSecretKey::allocate(
    ///         Complex64::new(0., 0.),
    ///         PolynomialSize(128),
    ///         GlweDimension(7),
    ///     );
    ///
    /// let mut buffers = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    /// let mut buffers_out = FourierBuffers::new(fourier_glwe.poly_size, fourier_glwe.glwe_size);
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(7),
    ///     PolynomialSize(128),
    ///     &mut secret_generator,
    /// );
    ///
    /// fourier_glwe.fill_with_forward_fourier(&secret_key, &mut buffers);
    ///
    /// let mut out_secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(7),
    ///     PolynomialSize(128),
    ///     &mut secret_generator,
    /// );
    ///
    /// fourier_glwe.fill_with_backward_fourier(&mut out_secret_key, &mut buffers_out);
    /// ```
    pub fn fill_with_backward_fourier<InputCont, Scalar_>(
        &mut self,
        glwe_key: &mut GlweSecretKey<Kind, InputCont>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        Cont: AsMutSlice<Element = Complex64>,
        GlweSecretKey<Kind, InputCont>: AsMutTensor<Element = Scalar_>,
        Scalar_: UnsignedTorus,
    {
        // We retrieve a buffer for the fft.
        let fft = &mut buffers.fft_buffers.fft;

        let mut poly_list = glwe_key.as_mut_polynomial_list();

        // we move every polynomial to the coefficient domain
        let iterator = poly_list
            .polynomial_iter_mut()
            .zip(self.polynomial_iter_mut());

        for (mut coef_poly, mut fourier_poly) in iterator {
            fft.backward_as_torus(&mut coef_poly, &mut fourier_poly);
        }
    }

    /// Returns an iterator over references to the polynomials contained in the GLWE key.
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

    /// Compute the tensor product between a secret key and itself.
    /// The output secret key has the same polynomial size, but its GLWE dimension is:
    /// k + k * (k + 1) / 2 + k with k the original GLWE dimension.
    pub fn create_tensor_product_key(
        &self,
    ) -> FourierGlweSecretKey<TensorProductKeyKind, AlignedVec<Complex64>, Scalar>
    where
        Self: AsRefTensor<Element = Complex64>,
        Cont: AsRefSlice,
    {

        let k = self.glwe_dimension().0;

        let mut fourier_output = FourierGlweSecretKey::allocate(
            Complex64::new(0., 0.),
            self.poly_size,
            GlweDimension(k + k * (k - 1) / 2 + k),
        );

        {
            let mut iter_output = fourier_output.polynomial_iter_mut();

            for (i, polyi) in self.polynomial_iter().enumerate() {
                let iter_2 = self.polynomial_iter();
                // consumes the iterator object with enumerate()
                for (j, polyj) in iter_2.enumerate() {
                    let mut iter_1_ = self.polynomial_iter();
                    if i == j {
                        // 1. T_i = A1i * A2i terms in the output have an s_i^2 key polynomial
                        let mut output_poly_1 = iter_output.next().unwrap();
                        output_poly_1.update_with_multiply_accumulate(&polyi, &polyi);
                        // 2. The A1i * B2 + B1 * A2i terms have an s_i key polynomial
                        let mut output_poly_2 = iter_output.next().unwrap();
                        // in this case we just need s_i, so we can access the original coefficient
                        output_poly_2.copy_polynomial_content(&polyi);
                    } else {
                        // else condition means i != j
                        if j < i {
                            let mut output_poly = iter_output.next().unwrap();
                            // we create the key terms of the form s_{i}s_{j} for the R_ij terms
                            output_poly.update_with_multiply_accumulate(&iter_1_.next().unwrap(),
                                                                         &polyj);
                        }
                    }
                }
            }
        }
        fourier_output
    }
}

impl<Element, Kind, Cont, Scalar> AsRefTensor for FourierGlweSecretKey<Kind, Cont, Scalar>
    where
        Cont: AsRefSlice<Element = Element>,
        Kind: KeyKind,
        Scalar: UnsignedTorus,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.tensor
    }
}

impl<Element, Kind, Cont, Scalar> AsMutTensor for FourierGlweSecretKey<Kind, Cont, Scalar>
    where
        Cont: AsMutSlice<Element = Element>,
        Kind: KeyKind,
        Scalar: UnsignedTorus,
{
    type Element = Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.tensor
    }
}

impl<Kind, Cont, Scalar> IntoTensor for FourierGlweSecretKey<Kind, Cont, Scalar>
    where
        Cont: AsRefSlice,
        Kind: KeyKind,
        Scalar: UnsignedTorus,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.tensor
    }
}
