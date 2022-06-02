use super::{
    mask_bytes_per_ggsw, mask_bytes_per_ggsw_level, mask_bytes_per_glwe, mask_bytes_per_gsw_level,
    mask_bytes_per_lwe, noise_bytes_per_ggsw, noise_bytes_per_ggsw_level, noise_bytes_per_glwe,
    noise_bytes_per_gsw_level, noise_bytes_per_lwe, DynamicEncryptionRandomGenerator,
    EncryptionRandomGenerator,
};
use crate::commons::math::random::{
    ByteRandomGenerator, RandomGenerator, RandomGeneratorParChildrenIterator,
};
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{
    DecompositionLevelCount, GlweSize, LweDimension, LweSize, PolynomialSize,
};
#[cfg(feature = "generator_x86_64_aesni")]
use concrete_csprng::generators::AesniRandomGenerator;
use concrete_csprng::generators::{ForkError, SoftwareRandomGenerator};
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
use rayon::prelude::*;

/// A type alias for the parallel children iterator type.
type ParChildrenIterator<G> = rayon::iter::Map<
    rayon::iter::Zip<RandomGeneratorParChildrenIterator<G>, RandomGeneratorParChildrenIterator<G>>,
    fn((RandomGenerator<G>, RandomGenerator<G>)) -> EncryptionRandomGenerator<G>,
>;

/// Result iterator for [`ParallelEncryptionRandomGeneratorInterface::par_try_fork`] when
/// implemented for [`EncryptionRandomGenerator`].
pub struct EncryptionRandomGeneratorParChildrenIterator<G: ByteRandomGenerator + Send>(
    ParChildrenIterator<G>,
);

impl<G: ByteRandomGenerator + Send> ParallelIterator
    for EncryptionRandomGeneratorParChildrenIterator<G>
{
    type Item = EncryptionRandomGenerator<G>;
    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        self.0.drive_unindexed(consumer)
    }
}

impl<G: ByteRandomGenerator + Send> IndexedParallelIterator
    for EncryptionRandomGeneratorParChildrenIterator<G>
{
    fn len(&self) -> usize {
        self.0.len()
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        self.0.drive(consumer)
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        self.0.with_producer(callback)
    }
}

/// Parallel counter-part of [`super::SequentialEncryptionRandomGeneratorInterface`].
pub trait ParallelEncryptionRandomGeneratorInterface {
    type ParChildrenIter: rayon::prelude::IndexedParallelIterator<Item = Self>;

    /// Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    fn par_fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw::<T>(level, glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        // panic!("{:?} {:?} {:?}", lwe_dimension.0, mask_bytes, noise_bytes);
        self.par_try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    fn par_fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw_level::<T>(glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.par_try_fork(level.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    fn par_fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), polynomial_size);
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.par_try_fork(glwe_size.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    fn par_fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_gsw_level::<T>(lwe_size);
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.par_try_fork(level.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    fn par_fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    /// Forks both generators into a parallel iterator.
    fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<Self::ParChildrenIter, ForkError>;
}

impl<G: ByteRandomGenerator + Send> ParallelEncryptionRandomGeneratorInterface
    for EncryptionRandomGenerator<G>
{
    type ParChildrenIter = EncryptionRandomGeneratorParChildrenIterator<G>;

    fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        // We try to fork the generators
        let mask_iter = self.mask.par_try_fork(n_child, mask_bytes)?;
        let noise_iter = self.noise.par_try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(EncryptionRandomGeneratorParChildrenIterator(
            mask_iter
                .zip(noise_iter)
                .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }),
        ))
    }
}

/// Parallel counter-part of [`super::DynamicEncryptionRandomGeneratorChildrenIterator`]
pub enum DynamicEncryptionRandomGeneratorParChildrenIterator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(EncryptionRandomGeneratorParChildrenIterator<AesniRandomGenerator>),
    Software(EncryptionRandomGeneratorParChildrenIterator<SoftwareRandomGenerator>),
}

impl ParallelIterator for DynamicEncryptionRandomGeneratorParChildrenIterator {
    type Item = DynamicEncryptionRandomGenerator;
    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGeneratorParChildrenIterator::Aesni(inner) => inner
                .map(DynamicEncryptionRandomGenerator::Aesni)
                .drive_unindexed(consumer),
            DynamicEncryptionRandomGeneratorParChildrenIterator::Software(inner) => inner
                .map(DynamicEncryptionRandomGenerator::Software)
                .drive_unindexed(consumer),
        }
    }
}

impl IndexedParallelIterator for DynamicEncryptionRandomGeneratorParChildrenIterator {
    fn len(&self) -> usize {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGeneratorParChildrenIterator::Aesni(inner) => inner.len(),
            DynamicEncryptionRandomGeneratorParChildrenIterator::Software(inner) => inner.len(),
        }
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGeneratorParChildrenIterator::Aesni(inner) => inner
                .map(DynamicEncryptionRandomGenerator::Aesni)
                .drive(consumer),
            DynamicEncryptionRandomGeneratorParChildrenIterator::Software(inner) => inner
                .map(DynamicEncryptionRandomGenerator::Software)
                .drive(consumer),
        }
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGeneratorParChildrenIterator::Aesni(inner) => inner
                .map(DynamicEncryptionRandomGenerator::Aesni)
                .with_producer(callback),
            DynamicEncryptionRandomGeneratorParChildrenIterator::Software(inner) => inner
                .map(DynamicEncryptionRandomGenerator::Software)
                .with_producer(callback),
        }
    }
}

impl ParallelEncryptionRandomGeneratorInterface for DynamicEncryptionRandomGenerator {
    type ParChildrenIter = DynamicEncryptionRandomGeneratorParChildrenIterator;

    fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGenerator::Aesni(inner) => {
                Ok(DynamicEncryptionRandomGeneratorParChildrenIterator::Aesni(
                    inner.par_try_fork(n_child, mask_bytes, noise_bytes)?,
                ))
            }
            DynamicEncryptionRandomGenerator::Software(inner) => {
                Ok(
                    DynamicEncryptionRandomGeneratorParChildrenIterator::Software(
                        inner.par_try_fork(n_child, mask_bytes, noise_bytes)?,
                    ),
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::commons::crypto::bootstrap::StandardBootstrapKey;
    use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::commons::test_tools::{
        new_encryption_random_generator, new_secret_random_generator,
    };
    use concrete_commons::dispersion::Variance;
    use concrete_commons::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    };

    #[test]
    fn test_gaussian_sampling_margin_factor_does_not_panic() {
        struct Params {
            glwe_size: GlweSize,
            poly_size: PolynomialSize,
            dec_level_count: DecompositionLevelCount,
            dec_base_log: DecompositionBaseLog,
            lwe_dim: LweDimension,
        }
        let params = Params {
            glwe_size: GlweSize(2),
            poly_size: PolynomialSize(1),
            dec_level_count: DecompositionLevelCount(1),
            dec_base_log: DecompositionBaseLog(4),
            lwe_dim: LweDimension(17000),
        };
        let mut enc_generator = new_encryption_random_generator();
        let mut sec_generator = new_secret_random_generator();
        let mut bsk = StandardBootstrapKey::allocate(
            0u32,
            params.glwe_size,
            params.poly_size,
            params.dec_level_count,
            params.dec_base_log,
            params.lwe_dim,
        );
        let lwe_sk = LweSecretKey::generate_binary(params.lwe_dim, &mut sec_generator);
        let glwe_sk = GlweSecretKey::generate_binary(
            params.glwe_size.to_glwe_dimension(),
            params.poly_size,
            &mut sec_generator,
        );
        bsk.par_fill_with_new_key(&lwe_sk, &glwe_sk, Variance(0.), &mut enc_generator);
    }
}
