use super::{GgswSeededLevelMatrix, StandardGgswCiphertext};
use crate::commons::math::decomposition::DecompositionLevel;
use crate::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Uniform,
};
use crate::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use concrete_commons::numeric::Numeric;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A GGSW seeded ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct StandardGgswSeededCiphertext<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    decomp_base_log: DecompositionBaseLog,
    compression_seed: CompressionSeed,
}

tensor_traits!(StandardGgswSeededCiphertext);

impl<Scalar> StandardGgswSeededCiphertext<Vec<Scalar>> {
    /// Allocates a new GGSW ciphertext whose coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.glwe_size(), glwe_size);
    /// assert_eq!(seeded_ggsw.decomposition_level_count(), decomp_level);
    /// assert_eq!(seeded_ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(seeded_ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(seeded_ggsw.compression_seed(), compression_seed);
    /// ```
    pub fn allocate(
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Scalar: Numeric,
    {
        // The factor 2 comes from the fact we need to keep the body and the polynomial containing
        // the message
        Self::from_container(
            vec![Scalar::ZERO; 2 * decomp_level.0 * glwe_size.0 * poly_size.0],
            poly_size,
            glwe_size,
            decomp_base_log,
            compression_seed,
        )
    }
}

impl<Cont> StandardGgswSeededCiphertext<Cont> {
    /// Creates a ggsw seeded ciphertext from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let container = vec![0u8; 2 * decomp_level.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::from_container(
    ///     container,
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.glwe_size(), glwe_size);
    /// assert_eq!(seeded_ggsw.decomposition_level_count(), decomp_level);
    /// assert_eq!(seeded_ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(seeded_ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(seeded_ggsw.compression_seed(), compression_seed);
    /// ```
    pub fn from_container(
        cont: Cont,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        decomp_base_log: DecompositionBaseLog,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => poly_size.0, glwe_size.0, 2);
        Self {
            tensor,
            glwe_size,
            poly_size,
            decomp_base_log,
            compression_seed,
        }
    }

    /// Returns the size of the glwe ciphertexts composing the ggsw ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.glwe_size(), glwe_size);
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the compression seed used to fill masks of the GLWE ciphertext making up the GGSW
    /// ciphertext.
    ///
    /// # Example
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.compression_seed(), compression_seed);
    /// ```
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Returns the number of decomposition levels used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.decomposition_level_count(), decomp_level);
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.glwe_size.0,
            self.poly_size.0,
            2
        );
        DecompositionLevelCount(self.as_tensor().len() / (2 * self.glwe_size.0 * self.poly_size.0))
    }

    /// Returns the size of the polynomials used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.polynomial_size(), polynomial_size);
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the logarithm of the base used for the gadget decomposition.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_ggsw.decomposition_base_log(), decomp_base_log);
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns an iterator over borrowed seeded level matrices.
    ///
    /// # Note
    ///
    /// This iterator iterates over the levels from the lower to the higher level in the usual
    /// order. To iterate in the reverse order, you can use `rev()` on the iterator.
    ///
    /// # Example
    ///
    /// Returns an iterator over mutably borrowed seeded level matrices.
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
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// for level_matrix in seeded_ggsw.level_matrix_iter() {
    ///     assert_eq!(level_matrix.row_iter().count(), glwe_size.0);
    ///     assert_eq!(level_matrix.polynomial_size(), polynomial_size);
    ///     for rlwe in level_matrix.row_iter() {
    ///         assert_eq!(rlwe.glwe_size(), glwe_size);
    ///         assert_eq!(rlwe.polynomial_size(), polynomial_size);
    ///     }
    /// }
    ///
    /// assert_eq!(seeded_ggsw.level_matrix_iter().count(), decomp_level.0);
    /// ```
    pub fn level_matrix_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = GgswSeededLevelMatrix<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        // The factor two is to get the coefficient with the message and the body with unpredictable
        // noise
        let chunks_size = 2 * self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let glwe_size = self.glwe_size;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswSeededLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    DecompositionLevel(index + 1),
                    self.compression_seed,
                )
            })
    }

    /// Returns an iterator over mutably borrowed seeded level matrices.
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
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// for mut level_matrix in seeded_ggsw.level_matrix_iter_mut() {
    ///     for mut rlwe in level_matrix.row_iter_mut() {
    ///         rlwe.as_mut_tensor().fill_with_element(9);
    ///     }
    /// }
    ///
    /// assert!(seeded_ggsw.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(seeded_ggsw.level_matrix_iter_mut().count(), 3);
    /// ```
    pub fn level_matrix_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = GgswSeededLevelMatrix<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        // The factor two is to get the coefficient with the message and the body with unpredictable
        // noise
        let chunks_size = 2 * self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let glwe_size = self.glwe_size;
        let compression_seed = self.compression_seed;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswSeededLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    DecompositionLevel(index + 1),
                    compression_seed,
                )
            })
    }

    /// Returns a parallel iterator over mutably borrowed level seeded matrices.
    ///
    /// # Notes
    /// This iterator is hidden behind the "multithread" feature gate.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use rayon::iter::ParallelIterator;
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// seeded_ggsw
    ///     .par_level_matrix_iter_mut()
    ///     .for_each(|mut level_matrix| {
    ///         for mut rlwe in level_matrix.row_iter_mut() {
    ///             rlwe.as_mut_tensor().fill_with_element(9);
    ///         }
    ///     });
    ///
    /// assert!(seeded_ggsw.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(seeded_ggsw.level_matrix_iter_mut().count(), 3);
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_level_matrix_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = GgswSeededLevelMatrix<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Sync + Send,
    {
        let chunks_size = 2 * self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let glwe_size = self.glwe_size;
        let compression_seed = self.compression_seed;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswSeededLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    DecompositionLevel(index + 1),
                    compression_seed,
                )
            })
    }

    pub fn expand_into_with_existing_generator<Scalar, OutCont, Gen>(
        self,
        output: &mut StandardGgswCiphertext<OutCont>,
        generator: &mut RandomGenerator<Gen>,
    ) where
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        StandardGgswCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        for (matrix_in, mut matrix_out) in
            self.level_matrix_iter().zip(output.level_matrix_iter_mut())
        {
            for (row_idx, (row_in, row_out)) in matrix_in
                .row_iter()
                .zip(matrix_out.row_iter_mut())
                .enumerate()
            {
                let mut glwe_out = row_out.into_glwe();

                let (mut output_body, mut output_mask) = glwe_out.get_mut_body_and_mask();

                let (poly_coeffs, glwe_body_in) = row_in.get_matrix_poly_coeffs();

                // generate a uniformly random mask
                generator.fill_tensor_with_random_uniform(output_mask.as_mut_tensor());

                output_body
                    .as_mut_tensor()
                    .as_mut_slice()
                    .clone_from_slice(glwe_body_in.as_tensor().as_slice());

                glwe_out
                    .as_mut_polynomial_list()
                    .get_mut_polynomial(row_idx)
                    .as_mut_tensor()
                    .fill_with_copy(poly_coeffs.as_tensor());
            }
        }
    }

    /// Returns the ciphertext as a full fledged GgswCiphertext
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use concrete_core::commons::crypto::ggsw::{
    ///     StandardGgswCiphertext, StandardGgswSeededCiphertext,
    /// };
    /// use concrete_core::commons::math::random::{CompressionSeed, Seed};
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_size = GlweSize(7);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ggsw = StandardGgswSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// let mut ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     polynomial_size,
    ///     glwe_size,
    ///     decomp_level,
    ///     decomp_base_log,
    /// );
    ///
    /// seeded_ggsw.expand_into::<_, _, SoftwareRandomGenerator>(&mut ggsw);
    ///
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level);
    /// ```
    pub fn expand_into<Scalar, OutCont, Gen>(self, output: &mut StandardGgswCiphertext<OutCont>)
    where
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        StandardGgswCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed().seed);

        self.expand_into_with_existing_generator(output, &mut generator);
    }
}
