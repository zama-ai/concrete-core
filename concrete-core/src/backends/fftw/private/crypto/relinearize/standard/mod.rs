use crate::commons::crypto::encoding::{PlaintextList};
use crate::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::commons::crypto::secret::{GlweSecretKey};
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::random::ByteRandomGenerator;
#[cfg(feature = "parallel")]
use crate::commons::math::random::ParallelByteRandomGenerator;
use crate::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::utils::{zip, zip_args};
use concrete_commons::dispersion::DispersionParameter;
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::numeric::Numeric;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};

#[cfg(feature = "parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
use crate::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use crate::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
use crate::backends::fftw::private::math::fft::{AlignedVec, Complex64, FourierPolynomial};
use crate::commons::crypto::glev::GlevListLevelMatrix;
use crate::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::prelude::{GlevCount, PlaintextCount};

/// A relinearization key represented in the standard domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardGlweRelinearizationKey<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    decomp_level: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
}

tensor_traits!(StandardGlweRelinearizationKey);

impl<Scalar> StandardGlweRelinearizationKey<Vec<Scalar>> {
    /// Allocates a new relinearization key in the standard domain whose polynomials coefficients
    /// are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::fftw::private::crypto::relinearize::StandardGlweRelinearizationKey;
    /// let rlk = StandardGlweRelinearizationKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    /// );
    /// assert_eq!(rlk.polynomial_size(), PolynomialSize(9));
    /// assert_eq!(rlk.glwe_size(), GlweSize(7));
    /// assert_eq!(rlk.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(rlk.base_log(), DecompositionBaseLog(5));
    /// assert_eq!(rlk.key_size(), LweDimension(4));
    /// ```
    pub fn allocate(
        value: Scalar,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> StandardGlweRelinearizationKey<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        // The relinearization key is a vector of (k^2 + k) / 2 Glevs
        // Each Glev is an array of size l (k + 1) N (l GLWE ciphertexts)
        let k = glwe_size.to_glwe_dimension().0;
        StandardGlweRelinearizationKey {
            tensor: Tensor::from_container(vec![
                value;
                decomp_level.0
                    * glwe_size.0
                    * poly_size.0
                    * (k * k + k) / 2
            ]),
            decomp_level,
            decomp_base_log,
            glwe_size,
            poly_size,
        }
    }
}

impl<Cont> StandardGlweRelinearizationKey<Cont> {
    /// Creates a relinearization key from an existing container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::fftw::private::crypto::relinearize::StandardGlweRelinearizationKey;
    /// let vector = vec![0u32; 10 * 5 * 4 * 4 * 15];
    /// let rlk = StandardGlweRelinearizationKey::from_container(
    ///     vector.as_slice(),
    ///     GlweSize(4),
    ///     PolynomialSize(10),
    ///     DecompositionLevelCount(5),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(rlk.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(rlk.glwe_size(), GlweSize(4));
    /// assert_eq!(rlk.level_count(), DecompositionLevelCount(5));
    /// assert_eq!(rlk.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn from_container<Coef>(
        cont: Cont,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> StandardGlweRelinearizationKey<Cont>
    where
        Cont: AsRefSlice<Element = Coef>,
        Coef: UnsignedTorus,
    {
        let k = glwe_size.to_glwe_dimension().0;
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() =>
            decomp_level.0,
            glwe_size.0,
            poly_size.0,
            (k * k + k) / 2
        );
        StandardGlweRelinearizationKey {
            tensor,
            glwe_size,
            poly_size,
            decomp_level,
            decomp_base_log,
        }
    }

    /// Generate a new relinearization key from the input parameters, and fills the current 
    /// container with it.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::dispersion::LogStandardDev;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::fftw::private::crypto::bootstrap::FourierBuffers;
    /// use concrete_core::backends::fftw::private::crypto::relinearize::StandardGlweRelinearizationKey;
    /// use concrete_core::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use concrete_core::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let (glwe_dim, poly_size) = (GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut rlk = StandardGlweRelinearizationKey::allocate(
    ///     9u32,
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    /// );
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// let mut buffers = FourierBuffers::new(rlk.polynomial_size(), rlk.glwe_size());
    /// rlk.fill_with_new_key(
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut encryption_generator,
    ///     &mut buffers,
    /// );
    /// ```
    pub fn fill_with_new_key<GlweCont, Scalar, Gen>(
        &mut self,
        glwe_secret_key: &GlweSecretKey<BinaryKeyKind, GlweCont>,
        noise_parameters: impl DispersionParameter,
        mut generator: &mut EncryptionRandomGenerator<Gen>,
        buffers: &mut FourierBuffers<Scalar>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, GlweCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.glwe_size.to_glwe_dimension().0 => glwe_secret_key.key_size().0);
        ck_dim_eq!(self.poly_size => glwe_secret_key.poly_size);
        self.as_mut_tensor()
            .fill_with_element(<Scalar as Numeric>::ZERO);
        
        // 1. Create a vector with the S_i x S_j polynomial multiplications in the standard domain

        // We retrieve a buffer for the fft
        let fft_buffer_1 = &mut buffers.fft_buffers.first_buffer;
        let fft_buffer_2 = &mut buffers.fft_buffers.second_buffer;
        let fft = &mut buffers.fft_buffers.fft;

        // Allocate a vector of polynomials that are will contain the secret key products S_i * S_j
        let k = self.glwe_size.to_glwe_dimension().0;
        let mut key_product_vec: Vec<Polynomial<Vec<Scalar>>> = Vec::with_capacity((k * k + k) / 2);
        for poly in key_product_vec.iter_mut() {
           poly.allocate(Scalar::ZERO, self.poly_size);
        }
        // Fill the vector with the products S_i * S_j, following the same ordering as the one of
        // the tensor product
        // TODO optimize this so as to make less Fourier conversions
        let mut iter_key_product_vec = key_product_vec.polynomial_iter_mut();
        let iter_1 = glwe_secret_key.polynomial_iter();
        for (i, poly_1) in iter_1.enumerate() {
            let iter_2 = glwe_secret_key.polynomial_iter();
            // consumes the iterator object with enumerate()
            for (j, poly_2) in iter_2.enumerate() {
                // The vector to encrypt is composed of the S_i S_j products with i = j or j < i
                if j <= i {
                    // Get the next item in the output
                    let mut output_poly = iter_key_product_vec.next().unwrap();
                    // Allocate a Fourier poly for the result of the polynomial product in the 
                    // Fourier domain
                    let mut fourier_output_poly =
                        FourierPolynomial::allocate(Complex64::zero(), self.poly_size);
                    // Convert the two key polynomials to the Fourier domain at once
                    fft.forward_two_as_integer(fft_buffer_1, fft_buffer_2, poly_1, poly_2);
                    // Compute the multiplication
                    fourier_output_poly.update_with_multiply_accumulate(&fft_buffer_1, 
                                                                        &fft_buffer_2);
                    // Convert the result back to the standard domain
                    fft.backward_as_torus(&mut output_poly, &mut fourier_output_poly);
                }
            }
        }

        // 2. Encrypt the vector of Si * Sj products in a vector of Glev ciphertexts
        let mut encoded = PlaintextList::allocate(Scalar::ZERO, PlaintextCount(self.poly_size
            .0 * (k * k + k) / 2));
        let mut encoded_iter = encoded.iter_mut();
        for poly in key_product_vec.iter() {
            for poly_coef in poly.coefficient_iter() {
                let mut plaintext = encoded_iter.next().unwrap();
                plaintext = poly_coef as Scalar;
            }
        }
        glwe_secret_key.create_relinearization_key(
            &mut self,
            &encoded,
            noise_parameters,
            &mut generator,
        );
    }

    /// Returns the size of the polynomials used in the relinearization key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let rlk = RelinearizationKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(rlk.polynomial_size(), PolynomialSize(9));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the size of the GLWE ciphertexts used in the relinearization key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let rlk = RelinearizationKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(rlk.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of levels used to decompose the key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let rlk = RelinearizationKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(rlk.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.decomp_level
    }

    /// Returns the logarithm of the base used to decompose the key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let rlk = RelinearizationKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(rlk.base_log(), DecompositionBaseLog(5));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns the amount of Glevs in the relinearization key
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// let rlk = RelinearizationKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    /// );
    /// assert_eq!(rlk.glev_count().0, (6 * 6 + 6) / 2);
    /// ```
    pub fn glev_count(&self) -> GlevCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.poly_size.0,
            self.glwe_size.0,
            self.decomp_level.0,
            self.glev_count.0,
        );
        let k = self.glwe_size().to_glwe_dimension().0;
        GlevCount(
            (k * k + k) / 2
        )
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
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswCiphertext;
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// for level_matrix in ggsw.level_matrix_iter() {
    ///     assert_eq!(level_matrix.row_iter().count(), 7);
    ///     assert_eq!(level_matrix.polynomial_size(), PolynomialSize(9));
    ///     for rlwe in level_matrix.row_iter() {
    ///         assert_eq!(rlwe.glwe_size(), GlweSize(7));
    ///         assert_eq!(rlwe.polynomial_size(), PolynomialSize(9));
    ///     }
    /// }
    /// assert_eq!(ggsw.level_matrix_iter().count(), 3);
    /// ```
    pub fn level_matrix_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = GlevListLevelMatrix<&[<Self as AsRefTensor>::Element]>>
        where
            Self: AsRefTensor,
    {
        let chunks_size = self.poly_size.0 * self.rlwe_size.0 * self.rlwe_size.0;
        let poly_size = self.poly_size;
        let rlwe_size = self.rlwe_size;
        let decomp_level = self.decomp_level;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GlevListLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    rlwe_size,
                    GlevCount(rlwe_size.0),
                    DecompositionLevel(decomp_level - index),
                )
            })
    }
    
    
    // TODO write mutable & parallel counterparts for level_matrix_iter

    // This function computes the product between input_poly and the (i, j) elements of the 
    // relinearization key for each decomposition level, outputting the result in output_poly
    pub(crate) fn compute_relinearization_product (
        &self,
        output_poly: &mut FourierGlweCiphertext<AlignedVec<Complex64>, Scalar>,
        input_poly: &Polynomial<Vec<Scalar>>,
        i: usize,
        j: usize,
        buffers: &mut FourierBuffers<Scalar>,
    ) {
        // "alias" buffers to save some typing
        let fft = &mut buffers.fft_buffers.fft;
        let rounded_buffer = &mut buffers.rounded_buffer;
        let first_fft_buffer = &mut buffers.fft_buffers.first_buffer;
        let second_fft_buffer = &mut buffers.fft_buffers.second_buffer;
        // Decompose the input polynomial
        let decomposer_t_i =
            SignedDecomposer::new(self.decomp_base_log, self.decomposition_level_count());
        decomposer_t_i.fill_tensor_with_closest_representable(rounded_buffer, &input_poly);

        // Perform the inner product between the RLK(i, j, l) element and the input polynomial in 
        // the Fourier domain, and accumulate the result in the output polynomial.
        let mut decomposition_t_i = decomposer_t_i.decompose_tensor(rounded_buffer);
        // We loop through the levels of the relinearization key
        for relin_decomp_matrix in self.level_matrix_iter() {
            // We retrieve the decomposition of this level.
            let t_i_decomp = decomposition_t_i.next_term().unwrap();
            // And convert it to the Fourier domain
            let mut t_i_decomp_fourier = FourierPolynomial::allocate(Complex64(0., 0.), rlk
                .polynomial_size());
            fft.forward_as_torus(&mut t_i_decomp_fourier, &t_i_decomp);
            debug_assert_eq!(
                relin_decomp_matrix.decomposition_level(),
                t_i_decomp.level()
            );
            // For each level we have to add the result of the product between the
            // decomposition of the polynomial, and the relinearization key level GLWE to the 
            // output.
            // When possible we iterate two times in a row, to benefit from the fact that fft can
            // transform two polynomials at once.
            let index_ij = self.get_relin_key_i_j_index(i, j);
            let mut iterator = relin_decomp_matrix.nth_row_iter(index_ij);
            loop {
                match (iterator.next(), iterator.next()) {
                    // Two iterates are available, we convert 2 polynomials from the RLK to 
                    // the Fourier domain at once
                    (Some(first), Some(second)) => {
                        // We perform the forward fft transform for the GLWE polynomials
                        fft.forward_two_as_integer(
                            first_fft_buffer,
                            second_fft_buffer,
                            &first,
                            &second,
                        );
                        output_poly.update_with_two_multiply_accumulate(
                            &t_i_decomp_fourier,
                            first_fft_buffer,
                            &t_i_decomp_fourier,
                            second_fft_buffer,
                        );
                    }
                    // We reach the  end of the loop and one element remains.
                    (Some(first), None) => {
                        // We perform the forward fft transform for the GLWE polynomial
                        fft.forward_as_integer(first_fft_buffer, &first);
                        output_poly.update_with_multiply_accumulate(
                            &t_i_decomp_fourier,
                            first_fft_buffer,
                        );
                    }
                    // The loop is over, we can exit.
                    _ => break,
                }
            }
        }
    }
    // This function returns the index of the T_i polynomial in a GLWE ciphertext that is the 
    // result of a tensor product. The A_i and R_ij indexes can be deduced easily:
    // A_i = T_i + 1
    // R_ij = (T_i + 1) + j + 1
    // i is the index of one polynomial of a GLWE of dimension k. The tensor product GLWE 
    // ciphertext has dimension (k^2 + k) / 2
    pub(crate) fn get_tensor_product_t_index (
        &self,
        i: usize,
    ) -> usize {
        // from i = 0 on, j = sum (i - k + 2, k = 1..i + 1)
        // for i = 0, j = 0
        let mut j = 0;
        if i > 0 {
            for k in 1..i + 1 {
                j += i - k + 2;
            }
        }
        j
    }

    // This function gets the index of the GLWE encrypting S_ij in the list of Glevs of the 
    // relinearization key corresponding to one level of decomposition.
    pub(crate) fn get_relin_key_i_j_index (
        &self,
        i: usize,
        j: usize
        ) -> usize {
            let mut k = 0;
            if i == j {
                k = self.get_tensor_product_t_index(i);
            } else {
                k = self.get_tensor_product_t_index(i) + j + 1;
            }
            k
        }
}
